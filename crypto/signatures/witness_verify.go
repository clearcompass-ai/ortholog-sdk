package signatures

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// Witness cosignature scheme tags.
const (
	SchemeECDSA byte = 0x01 // ECDSA over secp256k1 (individual signatures)
	SchemeBLS   byte = 0x02 // BLS over BLS12-381 (aggregate signature)
)

// WitnessVerifyResult holds per-signer verification results.
type WitnessVerifyResult struct {
	ValidCount int
	Total      int
	Results    []WitnessSignerResult
}

// WitnessSignerResult is the verification outcome for a single witness.
type WitnessSignerResult struct {
	PubKeyID [32]byte
	Valid    bool
	Err      error
}

// VerifyWitnessCosignatures verifies K-of-N witness cosignatures on a tree head.
// Dispatches on scheme tag: 0x01 ECDSA (K separate verifications),
// 0x02 BLS (aggregate verification via BLSVerifier interface).
// The cosigned message is the canonical 40-byte format (SDK-D14).
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

// BLSVerifier abstracts BLS12-381 signature verification.
// Concrete implementation provided by the operator or exchange.
type BLSVerifier interface {
	// VerifyAggregate verifies an aggregate BLS signature over a message
	// against a set of public keys. Returns per-key pass/fail.
	VerifyAggregate(msg []byte, signatures []types.WitnessSignature,
		pubkeys []types.WitnessPublicKey) ([]bool, error)
}

// verifyECDSACosignatures verifies individual ECDSA cosignatures.
func verifyECDSACosignatures(
	msg [40]byte,
	sigs []types.WitnessSignature,
	witnessKeys []types.WitnessPublicKey,
	K int,
) (*WitnessVerifyResult, error) {
	// Build lookup: pubkey ID -> parsed public key.
	keyMap := make(map[[32]byte]*ecdsa.PublicKey, len(witnessKeys))
	for _, wk := range witnessKeys {
		pk, err := ParsePubKey(wk.PublicKey)
		if err != nil {
			continue // Skip unparseable keys.
		}
		keyMap[wk.ID] = pk
	}

	// Hash the 40-byte message for ECDSA verification.
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
		err := VerifyEntry(msgHash, ws.SigBytes, pk)
		if err != nil {
			result.Results[i].Err = err
			continue
		}
		result.Results[i].Valid = true
		result.ValidCount++
	}

	if result.ValidCount < K {
		return result, fmt.Errorf("only %d of required %d witness signatures valid", result.ValidCount, K)
	}
	return result, nil
}

// verifyBLSCosignatures verifies aggregate BLS cosignatures via the BLSVerifier interface.
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
		return vr, fmt.Errorf("only %d of required %d BLS witness signatures valid", vr.ValidCount, K)
	}
	return vr, nil
}
