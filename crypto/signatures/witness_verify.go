/*
FILE PATH:

	crypto/signatures/witness_verify.go

DESCRIPTION:

	Witness cosignature primitives. Signing and verification for
	tree head cosignatures produced by witness services (and, for
	testing, by test fixtures standing in for witnesses).

	Two signing schemes:
	  SchemeECDSA (0x01) — secp256k1, 64-byte raw R||S via SignEntry.
	  SchemeBLS   (0x02) — aggregate BLS signatures via injected verifier.

	Signing is exposed only for ECDSA because BLS signing requires
	scheme-specific aggregation logic outside this file's scope.

KEY ARCHITECTURAL DECISIONS:
  - Verify and sign paths use the same message construction:
    msg    = types.WitnessCosignMessage(head)  // 40 bytes
    digest = sha256.Sum256(msg[:])
    sig    = SignEntry(digest, privkey)
    This consolidation matters: a previous iteration of the SDK had
    the signing convention implicit in the verify path, forcing
    every signer (test fixtures, witness services) to reinvent it.
    A drift in any signer's hash choice would silently produce
    signatures that verify nowhere. Exposing SignWitnessCosignature
    as the single source of truth closes that gap.
  - ECDSA path: any signature produced by SignWitnessCosignature is
    accepted by VerifyWitnessCosignatures using the matching public
    key. Symmetric round-trip is load-bearing.
  - BLS path is verify-only at the primitive level. BLS witness
    implementations inject their own BLSVerifier satisfying the
    interface; SDK does not bundle a BLS library.
  - K-of-N quorum enforced at the VerifyWitnessCosignatures level:
    at least K signatures must verify, out of the N provided. All
    N are checked regardless (so diagnostic results are complete),
    but the function returns error if fewer than K pass.

OVERVIEW:

	Witness signing (ECDSA):
	    sig, err := SignWitnessCosignature(head, privkey)
	    // sig is 64-byte R||S, low-S normalized.

	Witness verification:
	    result, err := VerifyWitnessCosignatures(cosigned, keys, K, blsVer)
	    // result.ValidCount >= K on success; err reports which sigs failed.

KEY DEPENDENCIES:
  - crypto/signatures/entry_verify.go: SignEntry, VerifyEntry, ParsePubKey
  - types.CosignedTreeHead, types.TreeHead, types.WitnessSignature,
    types.WitnessPublicKey, types.WitnessCosignMessage
*/
package signatures

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) Scheme tags
// -------------------------------------------------------------------------------------------------

// Witness signature scheme tags, carried in CosignedTreeHead.SchemeTag.
// Values are protocol-permanent — changing them invalidates every
// cosigned tree head ever produced.
const (
	SchemeECDSA byte = 0x01 // secp256k1, 64-byte raw R||S
	SchemeBLS   byte = 0x02 // BLS aggregate (verify-only in SDK)
)

// -------------------------------------------------------------------------------------------------
// 2) Verification result types
// -------------------------------------------------------------------------------------------------

// WitnessVerifyResult is the diagnostic return value from
// VerifyWitnessCosignatures. Carries per-signer verification outcomes
// for monitoring, auditing, and error reporting.
type WitnessVerifyResult struct {
	ValidCount int
	Total      int
	Results    []WitnessSignerResult
}

// WitnessSignerResult is the per-signature verification outcome.
type WitnessSignerResult struct {
	PubKeyID [32]byte
	Valid    bool
	Err      error
}

// -------------------------------------------------------------------------------------------------
// 3) BLSVerifier interface — injection point for BLS implementations
// -------------------------------------------------------------------------------------------------

// BLSVerifier verifies aggregate BLS cosignatures. Implementations
// wrap a BLS library (BLS12-381, BN254, etc.) and are supplied by
// the witness runtime. The SDK does not bundle a BLS library.
type BLSVerifier interface {
	VerifyAggregate(msg []byte, signatures []types.WitnessSignature, pubkeys []types.WitnessPublicKey) ([]bool, error)
}

// -------------------------------------------------------------------------------------------------
// 4) SignWitnessCosignature — ECDSA signing primitive
// -------------------------------------------------------------------------------------------------

// SignWitnessCosignature produces an ECDSA witness cosignature over a
// TreeHead using the scheme convention:
//
//	msg    = types.WitnessCosignMessage(head)  // 40 bytes
//	digest = sha256.Sum256(msg)
//	sig    = SignEntry(digest, privkey)        // 64-byte R||S, low-S
//
// The returned 64-byte signature, when paired with the matching
// public key in a types.WitnessSignature and carried in a
// CosignedTreeHead with SchemeTag == SchemeECDSA, verifies
// successfully via VerifyWitnessCosignatures.
//
// Matches verifyECDSACosignatures exactly. Any drift between this
// signer and that verifier would be a protocol-level bug; the
// round-trip test in witness_verify_test.go guards against it.
//
// BLS signing is not provided here. BLS cosigners produce signatures
// through their own aggregation workflow and hand the result to
// whatever witness service is being tested.
//
// Callers:
//   - witness services producing real cosignatures in production
//   - test fixtures building verifiable tree heads (e.g.,
//     verifier/cross_log_test.go buildWellFormedProof)
//   - any future component that needs to cosign a tree head with
//     an ECDSA key
func SignWitnessCosignature(head types.TreeHead, privkey *ecdsa.PrivateKey) ([]byte, error) {
	if privkey == nil {
		return nil, errors.New("signatures: SignWitnessCosignature requires non-nil private key")
	}
	msg := types.WitnessCosignMessage(head)
	digest := sha256.Sum256(msg[:])
	return SignEntry(digest, privkey)
}

// -------------------------------------------------------------------------------------------------
// 5) VerifyWitnessCosignatures — dispatcher by scheme tag
// -------------------------------------------------------------------------------------------------

// VerifyWitnessCosignatures verifies the cosignatures on a tree head
// against a set of witness public keys, enforcing a K-of-N quorum.
//
// Dispatches by head.SchemeTag:
//   - SchemeECDSA: calls verifyECDSACosignatures (secp256k1 + SignEntry)
//   - SchemeBLS:   calls verifyBLSCosignatures (via injected BLSVerifier)
//
// Returns a WitnessVerifyResult describing every signature's outcome
// for diagnostics. Returns a non-nil error when fewer than K
// signatures verify; the result is still populated for introspection.
func VerifyWitnessCosignatures(
	head types.CosignedTreeHead,
	witnessKeys []types.WitnessPublicKey,
	K int,
	blsVerifier BLSVerifier,
) (*WitnessVerifyResult, error) {
	if K <= 0 {
		return nil, errors.New("K must be positive")
	}
	if len(head.Signatures) == 0 {
		return nil, errors.New("no cosignatures present")
	}
	msg := types.WitnessCosignMessage(head.TreeHead)
	switch head.SchemeTag {
	case SchemeECDSA:
		return verifyECDSACosignatures(msg, head.Signatures, witnessKeys, K)
	case SchemeBLS:
		if blsVerifier == nil {
			return nil, errors.New("BLS verifier required for scheme 0x02")
		}
		return verifyBLSCosignatures(msg, head.Signatures, witnessKeys, K, blsVerifier)
	default:
		return nil, fmt.Errorf("unknown witness scheme tag 0x%02x", head.SchemeTag)
	}
}

// -------------------------------------------------------------------------------------------------
// 6) verifyECDSACosignatures — SchemeECDSA implementation
// -------------------------------------------------------------------------------------------------

func verifyECDSACosignatures(
	msg [40]byte,
	sigs []types.WitnessSignature,
	witnessKeys []types.WitnessPublicKey,
	K int,
) (*WitnessVerifyResult, error) {
	// Index witness public keys by their 32-byte ID for O(1) lookup
	// during per-signature verification. Keys that fail to parse are
	// dropped from the index — their signatures will surface as
	// "unknown witness public key" diagnostics.
	keyMap := make(map[[32]byte]*ecdsa.PublicKey, len(witnessKeys))
	for _, wk := range witnessKeys {
		pk, err := ParsePubKey(wk.PublicKey)
		if err != nil {
			continue
		}
		keyMap[wk.ID] = pk
	}

	// Digest construction mirrors SignWitnessCosignature exactly.
	msgHash := sha256.Sum256(msg[:])

	result := &WitnessVerifyResult{
		Total:   len(sigs),
		Results: make([]WitnessSignerResult, len(sigs)),
	}
	for i, ws := range sigs {
		result.Results[i].PubKeyID = ws.PubKeyID

		pk, ok := keyMap[ws.PubKeyID]
		if !ok {
			result.Results[i].Err = errors.New("unknown witness public key")
			continue
		}
		if len(ws.SigBytes) != 64 {
			result.Results[i].Err = fmt.Errorf("expected 64-byte signature, got %d", len(ws.SigBytes))
			continue
		}
		if err := VerifyEntry(msgHash, ws.SigBytes, pk); err != nil {
			result.Results[i].Err = err
			continue
		}
		result.Results[i].Valid = true
		result.ValidCount++
	}

	if result.ValidCount < K {
		return result, fmt.Errorf("only %d of required %d witness signatures valid",
			result.ValidCount, K)
	}
	return result, nil
}

// -------------------------------------------------------------------------------------------------
// 7) verifyBLSCosignatures — SchemeBLS implementation
// -------------------------------------------------------------------------------------------------

func verifyBLSCosignatures(
	msg [40]byte,
	sigs []types.WitnessSignature,
	witnessKeys []types.WitnessPublicKey,
	K int,
	verifier BLSVerifier,
) (*WitnessVerifyResult, error) {
	results, err := verifier.VerifyAggregate(msg[:], sigs, witnessKeys)
	if err != nil {
		return nil, fmt.Errorf("BLS aggregate verification: %w", err)
	}

	vr := &WitnessVerifyResult{
		Total:   len(sigs),
		Results: make([]WitnessSignerResult, len(sigs)),
	}
	for i, valid := range results {
		if i < len(sigs) {
			vr.Results[i].PubKeyID = sigs[i].PubKeyID
		}
		vr.Results[i].Valid = valid
		if valid {
			vr.ValidCount++
		}
	}

	if vr.ValidCount < K {
		return vr, fmt.Errorf("only %d of required %d BLS witness signatures valid",
			vr.ValidCount, K)
	}
	return vr, nil
}
