package signatures

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

const (
	SchemeECDSA byte = 0x01
	SchemeBLS   byte = 0x02
)

type WitnessVerifyResult struct { ValidCount int; Total int; Results []WitnessSignerResult }
type WitnessSignerResult struct { PubKeyID [32]byte; Valid bool; Err error }

type BLSVerifier interface {
	VerifyAggregate(msg []byte, signatures []types.WitnessSignature, pubkeys []types.WitnessPublicKey) ([]bool, error)
}

func VerifyWitnessCosignatures(head types.CosignedTreeHead, witnessKeys []types.WitnessPublicKey, K int, blsVerifier BLSVerifier) (*WitnessVerifyResult, error) {
	if K <= 0 { return nil, errors.New("K must be positive") }
	if len(head.Signatures) == 0 { return nil, errors.New("no cosignatures present") }
	msg := types.WitnessCosignMessage(head.TreeHead)
	switch head.SchemeTag {
	case SchemeECDSA: return verifyECDSACosignatures(msg, head.Signatures, witnessKeys, K)
	case SchemeBLS:
		if blsVerifier == nil { return nil, errors.New("BLS verifier required for scheme 0x02") }
		return verifyBLSCosignatures(msg, head.Signatures, witnessKeys, K, blsVerifier)
	default: return nil, fmt.Errorf("unknown witness scheme tag 0x%02x", head.SchemeTag)
	}
}

func verifyECDSACosignatures(msg [40]byte, sigs []types.WitnessSignature, witnessKeys []types.WitnessPublicKey, K int) (*WitnessVerifyResult, error) {
	keyMap := make(map[[32]byte]*ecdsa.PublicKey, len(witnessKeys))
	for _, wk := range witnessKeys {
		pk, err := ParsePubKey(wk.PublicKey)
		if err != nil { continue }
		keyMap[wk.ID] = pk
	}
	msgHash := sha256.Sum256(msg[:])
	result := &WitnessVerifyResult{Total: len(sigs), Results: make([]WitnessSignerResult, len(sigs))}
	for i, ws := range sigs {
		result.Results[i].PubKeyID = ws.PubKeyID
		pk, ok := keyMap[ws.PubKeyID]
		if !ok { result.Results[i].Err = errors.New("unknown witness public key"); continue }
		if len(ws.SigBytes) != 64 { result.Results[i].Err = fmt.Errorf("expected 64-byte signature, got %d", len(ws.SigBytes)); continue }
		if err := VerifyEntry(msgHash, ws.SigBytes, pk); err != nil { result.Results[i].Err = err; continue }
		result.Results[i].Valid = true; result.ValidCount++
	}
	if result.ValidCount < K { return result, fmt.Errorf("only %d of required %d witness signatures valid", result.ValidCount, K) }
	return result, nil
}

func verifyBLSCosignatures(msg [40]byte, sigs []types.WitnessSignature, witnessKeys []types.WitnessPublicKey, K int, verifier BLSVerifier) (*WitnessVerifyResult, error) {
	results, err := verifier.VerifyAggregate(msg[:], sigs, witnessKeys)
	if err != nil { return nil, fmt.Errorf("BLS aggregate verification: %w", err) }
	vr := &WitnessVerifyResult{Total: len(sigs), Results: make([]WitnessSignerResult, len(sigs))}
	for i, valid := range results {
		if i < len(sigs) { vr.Results[i].PubKeyID = sigs[i].PubKeyID }
		vr.Results[i].Valid = valid
		if valid { vr.ValidCount++ }
	}
	if vr.ValidCount < K { return vr, fmt.Errorf("only %d of required %d BLS witness signatures valid", vr.ValidCount, K) }
	return vr, nil
}
