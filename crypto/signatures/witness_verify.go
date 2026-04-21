/*
FILE PATH:

	crypto/signatures/witness_verify.go

DESCRIPTION:

	Witness cosignature primitives: ECDSA signing primitive for
	test fixtures and witness services, and the per-signature
	verification dispatcher that routes each signature to its
	scheme-specific verifier.

	Two signing schemes are currently supported by the dispatcher:

	  SchemeECDSA (0x01) — secp256k1, 64-byte raw R||S via SignEntry.
	  SchemeBLS   (0x02) — aggregate BLS via injected verifier.

	BLS signing lives in bls_signer.go. This file exposes only
	SignWitnessCosignature (ECDSA) because the BLS path is
	implementation-defined by the injected verifier. ECDSA signing
	is still needed here as the reference implementation used by
	every test fixture that constructs verifiable cosigned tree heads.

WAVE 2 CHANGE: Per-signature dispatch

	Pre-Wave-2 this file contained two monolithic helpers —
	verifyECDSACosignatures and verifyBLSCosignatures — each of
	which verified ALL signatures in a cosigned head under a single
	scheme (read from head.SchemeTag). That forced every witness in
	a single head to use the same scheme.

	Post-Wave-2 the dispatcher reads each signature's SchemeTag
	independently. Every signature in a single head may declare a
	different scheme. ECDSA signatures verify inline one at a time;
	BLS signatures queue for batched aggregate verification so the
	BLS optimistic-aggregation optimization still applies.

	This refactor is the core architectural payoff of the Wave 1
	cryptographic work: deployments can now migrate individual
	witnesses between schemes without coordinating a synchronized
	all-or-nothing transition across the entire witness set.

KEY ARCHITECTURAL DECISIONS:

  - Strict zero-tag rejection. Signatures with SchemeTag == 0 are
    rejected with a typed error before any cryptographic work is
    attempted. No defensive populate, no "migration fallback." The
    scheme is required to be declared explicitly.

  - Strict unknown-tag rejection. Signatures with SchemeTag values
    that the dispatcher does not recognize are rejected with a
    typed error. Future scheme additions must propagate through the
    dispatcher's switch statement deliberately; silent acceptance
    of unknown tags would mask protocol errors.

  - BLS signatures batch-verify. When one or more signatures in a
    head declare SchemeBLS, all BLS signatures are gathered and
    passed as a single batch to the injected BLSVerifier. This
    preserves the O(1)-pairing happy path from Wave 1's same-
    message aggregation optimization. A head with 3 ECDSA + 5 BLS
    signatures pays 3 pairings worth of ECDSA verification plus
    1 pairing check for the BLS batch (happy path), not 8.

  - Parallel results slice. WitnessVerifyResult.Results is indexed
    to match the input head.Signatures slice exactly. Callers can
    correlate input signatures with outcomes by index without
    needing to inspect PubKeyID.

  - BLS verifier may be nil only if no BLS signatures are present.
    Pre-Wave-2 the verifier was required when head.SchemeTag ==
    SchemeBLS; post-Wave-2 it's required when ANY signature
    declares SchemeBLS. Heads with only ECDSA signatures work
    without a BLS verifier injected.

  - K-of-N quorum counted across all schemes. A head with 2 valid
    ECDSA signatures + 1 valid BLS signature satisfies K=3
    regardless of scheme mix.

OVERVIEW:

	Witness signing (ECDSA):
	    sig, err := SignWitnessCosignature(head, privkey)
	    // sig is 64-byte R||S, low-S normalized.
	    // Caller wraps in WitnessSignature{SchemeTag: SchemeECDSA, ...}

	Witness verification:
	    result, err := VerifyWitnessCosignatures(cosigned, keys, K, blsVer)
	    // result.ValidCount >= K on success.
	    // err describes quorum failure; result.Results has per-sig detail.

KEY DEPENDENCIES:
  - crypto/signatures/entry_verify.go: SignEntry, VerifyEntry, ParsePubKey
  - crypto/signatures/bls_verifier.go: BLSVerifier implementations
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
// 1) Scheme tags — locked by bls_gaps_test.go TestSchemeBLS_Value / TestSchemeECDSA_Value
// -------------------------------------------------------------------------------------------------

// Witness signature scheme tags, carried in WitnessSignature.SchemeTag
// (Wave 2). Values are protocol-permanent — changing them invalidates
// every cosigned tree head ever produced under the current protocol
// version.
//
// The zero value (0x00) is deliberately NOT assigned to any scheme;
// it is reserved for "scheme not declared" and is rejected by the
// verifier dispatch.
const (
	SchemeECDSA byte = 0x01 // secp256k1, 64-byte raw R||S, low-S normalized
	SchemeBLS   byte = 0x02 // BLS12-381 aggregate, 48-byte compressed G1
)

// -------------------------------------------------------------------------------------------------
// 2) Verification result types
// -------------------------------------------------------------------------------------------------

// WitnessVerifyResult is the diagnostic return value from
// VerifyWitnessCosignatures. Carries per-signature outcomes for
// monitoring, auditing, and error reporting.
//
// Results is parallel to the input head.Signatures slice: Results[i]
// corresponds to head.Signatures[i]. ValidCount and Total are
// derived aggregates; Total == len(head.Signatures), ValidCount
// counts entries where Results[i].Valid is true.
type WitnessVerifyResult struct {
	ValidCount int
	Total      int
	Results    []WitnessSignerResult
}

// WitnessSignerResult is the per-signature verification outcome.
// On success, Valid is true and Err is nil. On failure, Valid is
// false and Err describes the failure reason (unknown key, bad
// length, pairing failure, unknown scheme, zero scheme, etc.).
type WitnessSignerResult struct {
	PubKeyID [32]byte
	Valid    bool
	Err      error
}

// -------------------------------------------------------------------------------------------------
// 3) BLSVerifier interface — injection point for BLS implementations
// -------------------------------------------------------------------------------------------------

// BLSVerifier verifies aggregate BLS cosignatures. Implementations
// wrap a BLS library (BLS12-381 via gnark-crypto is the production
// implementation in bls_verifier.go). The SDK does not bundle a BLS
// library by default; callers inject the verifier.
//
// VerifyAggregate contract: returns []bool parallel to signatures
// and pubkeys, with results[i] == true iff signatures[i] verified
// under pubkeys[i]. Non-nil error only for transport-level failures;
// individual signature invalidity is results[i] == false, not an
// error.
type BLSVerifier interface {
	VerifyAggregate(msg []byte, signatures []types.WitnessSignature, pubkeys []types.WitnessPublicKey) ([]bool, error)
}

// -------------------------------------------------------------------------------------------------
// 4) SignWitnessCosignature — ECDSA signing primitive
// -------------------------------------------------------------------------------------------------

// SignWitnessCosignature produces an ECDSA witness cosignature over
// a TreeHead using the scheme convention:
//
//	msg    = types.WitnessCosignMessage(head)  // 40 bytes
//	digest = sha256.Sum256(msg[:])
//	sig    = SignEntry(digest, privkey)        // 64-byte R||S, low-S
//
// The returned 64-byte signature, when paired with the matching
// public key and a SchemeTag of SchemeECDSA in a
// types.WitnessSignature, verifies successfully via
// VerifyWitnessCosignatures.
//
// Symmetric round-trip with the verifier is load-bearing: any drift
// between this signer's digest construction and the dispatcher's
// verification digest would silently break every ECDSA cosignature.
// TestSignWitnessCosignature_RoundTrip in witness_verify_test.go
// guards against this drift.
//
// BLS signing is in bls_signer.go (SignBLSCosignature). A caller
// building a mixed-scheme WitnessSignature slice calls both signing
// primitives and sets SchemeTag appropriately on each output:
//
//	ecdsaSig, _ := SignWitnessCosignature(head, ecdsaPriv)
//	blsSig,   _ := SignBLSCosignature(head, blsPriv)
//	sigs := []WitnessSignature{
//	    {PubKeyID: id1, SchemeTag: SchemeECDSA, SigBytes: ecdsaSig},
//	    {PubKeyID: id2, SchemeTag: SchemeBLS,   SigBytes: blsSig},
//	}
//
// Callers:
//   - witness services producing real cosignatures in production
//   - test fixtures building verifiable tree heads
//   - witness migration tooling producing dual-sign rotations
func SignWitnessCosignature(head types.TreeHead, privkey *ecdsa.PrivateKey) ([]byte, error) {
	if privkey == nil {
		return nil, errors.New("signatures: SignWitnessCosignature requires non-nil private key")
	}
	msg := types.WitnessCosignMessage(head)
	digest := sha256.Sum256(msg[:])
	return SignEntry(digest, privkey)
}

// -------------------------------------------------------------------------------------------------
// 5) VerifyWitnessCosignatures — per-signature dispatcher
// -------------------------------------------------------------------------------------------------

// VerifyWitnessCosignatures verifies the cosignatures on a tree
// head against a set of witness public keys, enforcing a K-of-N
// quorum where validity is counted across all schemes.
//
// # DISPATCH MODEL (Wave 2)
//
// Each signature in head.Signatures is dispatched independently
// based on its SchemeTag:
//
//	SchemeECDSA → verify inline using secp256k1 + SignEntry digest
//	SchemeBLS   → queue for batched aggregate verification
//	0x00        → REJECTED: scheme not declared
//	other       → REJECTED: unknown scheme
//
// After all ECDSA signatures are verified inline, any queued BLS
// signatures are verified in a single batched call to the injected
// BLSVerifier. This preserves the O(1)-pairing happy path from
// Wave 1's same-message aggregation optimization.
//
// # VALIDITY ACCOUNTING
//
// The K-of-N quorum counts all valid signatures regardless of
// scheme. A head with 2 valid ECDSA signatures and 1 valid BLS
// signature satisfies K=3. Invalid signatures (any reason) do not
// count toward the quorum.
//
// # BLS VERIFIER REQUIREMENT
//
// The blsVerifier argument is required iff at least one signature
// in head.Signatures declares SchemeBLS. Heads with only ECDSA
// signatures can be verified with blsVerifier == nil. If a BLS
// signature is present and blsVerifier is nil, the BLS signatures
// all record an error ("BLSVerifier required but nil") and are
// treated as invalid; the function continues to produce a full
// diagnostic result for the ECDSA signatures.
//
// # RESULT STRUCTURE
//
// Returns *WitnessVerifyResult with Results parallel to
// head.Signatures. On quorum failure (ValidCount < K) returns a
// non-nil error in addition to the populated result — the caller
// can inspect per-signature outcomes regardless of overall success.
//
// On quorum success, err is nil.
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

	// Compute the signed message once. Every signature in the head
	// (regardless of scheme) signs this exact byte sequence.
	msg := types.WitnessCosignMessage(head.TreeHead)
	msgHash := sha256.Sum256(msg[:]) // ECDSA consumes the SHA-256 digest

	// Build lookup maps once:
	//   - keyMap:       PubKeyID → full WitnessPublicKey (needed by BLS verifier)
	//   - ecdsaParsed:  PubKeyID → parsed *ecdsa.PublicKey (ECDSA fast path)
	//
	// ECDSA keys that fail to parse are silently dropped from the
	// parsed map but kept in keyMap. A signature referencing such a
	// key will surface as "unknown witness public key" in its result
	// entry, matching the pre-Wave-2 diagnostic behavior.
	keyMap := make(map[[32]byte]types.WitnessPublicKey, len(witnessKeys))
	ecdsaParsed := make(map[[32]byte]*ecdsa.PublicKey, len(witnessKeys))
	for _, wk := range witnessKeys {
		keyMap[wk.ID] = wk
		if pk, err := ParsePubKey(wk.PublicKey); err == nil {
			ecdsaParsed[wk.ID] = pk
		}
	}

	// Initialize the parallel result structure. Every slot starts as
	// invalid; only successful verifications flip Valid=true.
	result := &WitnessVerifyResult{
		Total:   len(head.Signatures),
		Results: make([]WitnessSignerResult, len(head.Signatures)),
	}

	// BLS signatures queue for batched verification. We record the
	// original index so we can write results back to the correct
	// parallel slot after VerifyAggregate returns.
	blsIndices := []int{}
	blsSigs := []types.WitnessSignature{}
	blsPubs := []types.WitnessPublicKey{}

	// ────────────────────────────────────────────────────────────
	// First pass: ECDSA inline + BLS queueing
	// ────────────────────────────────────────────────────────────
	for i, ws := range head.Signatures {
		result.Results[i].PubKeyID = ws.PubKeyID

		// Strict zero-tag rejection. The scheme MUST be declared.
		// No defensive populate, no fallback to a "default" scheme.
		if ws.SchemeTag == 0 {
			result.Results[i].Err = fmt.Errorf(
				"signature %d has zero SchemeTag (must be SchemeECDSA=0x01 or SchemeBLS=0x02)", i)
			continue
		}

		switch ws.SchemeTag {
		case SchemeECDSA:
			// Inline ECDSA verification.
			pk, ok := ecdsaParsed[ws.PubKeyID]
			if !ok {
				result.Results[i].Err = errors.New("unknown witness public key")
				continue
			}
			if len(ws.SigBytes) != 64 {
				result.Results[i].Err = fmt.Errorf(
					"expected 64-byte ECDSA signature, got %d", len(ws.SigBytes))
				continue
			}
			if err := VerifyEntry(msgHash, ws.SigBytes, pk); err != nil {
				result.Results[i].Err = err
				continue
			}
			result.Results[i].Valid = true
			result.ValidCount++

		case SchemeBLS:
			// Queue for batched BLS aggregate verification. We must
			// resolve the public key now (not later) because the
			// BLSVerifier interface takes parallel slices of
			// signatures and pubkeys; mismatched keys would corrupt
			// the batch.
			wk, ok := keyMap[ws.PubKeyID]
			if !ok {
				result.Results[i].Err = errors.New("unknown witness public key")
				continue
			}
			blsIndices = append(blsIndices, i)
			blsSigs = append(blsSigs, ws)
			blsPubs = append(blsPubs, wk)

		default:
			// Strict unknown-scheme rejection. Future scheme
			// additions must propagate through this switch
			// deliberately; silent acceptance would mask protocol
			// errors.
			result.Results[i].Err = fmt.Errorf(
				"unknown scheme tag 0x%02x (expected SchemeECDSA=0x01 or SchemeBLS=0x02)",
				ws.SchemeTag)
		}
	}

	// ────────────────────────────────────────────────────────────
	// Second pass: batched BLS aggregate verification
	// ────────────────────────────────────────────────────────────
	if len(blsSigs) > 0 {
		if blsVerifier == nil {
			// BLS signatures are present but no verifier was
			// injected. Mark every queued BLS signature as invalid
			// with a diagnostic error; the ECDSA signatures remain
			// valid if they were valid.
			for _, idx := range blsIndices {
				result.Results[idx].Err = errors.New(
					"BLSVerifier required for BLS signature but nil was provided")
			}
		} else {
			blsResults, err := blsVerifier.VerifyAggregate(msg[:], blsSigs, blsPubs)
			if err != nil {
				// Transport-level BLS verification failure (e.g.,
				// pairing library error). Every queued BLS signature
				// gets the error recorded; ECDSA results are
				// unaffected.
				for _, idx := range blsIndices {
					result.Results[idx].Err = fmt.Errorf("BLS aggregate: %w", err)
				}
			} else {
				// Write BLS outcomes back to the parallel result
				// slots. VerifyAggregate's contract is blsResults[j]
				// parallel to (blsSigs, blsPubs), so blsIndices[j]
				// identifies the original position in head.Signatures.
				for j, valid := range blsResults {
					idx := blsIndices[j]
					result.Results[idx].Valid = valid
					if valid {
						result.ValidCount++
					} else {
						result.Results[idx].Err = errors.New(
							"BLS signature verification failed")
					}
				}
			}
		}
	}

	// ────────────────────────────────────────────────────────────
	// Quorum check
	// ────────────────────────────────────────────────────────────
	if result.ValidCount < K {
		return result, fmt.Errorf("only %d of required %d witness signatures valid",
			result.ValidCount, K)
	}
	return result, nil
}
