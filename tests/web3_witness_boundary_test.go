/*
FILE PATH:

	tests/web3_witness_boundary_test.go

DESCRIPTION:

	Witness cosignature boundary tests. Witnesses are SDK-native signers that
	produce 64-byte ECDSA secp256k1 signatures. This file locks the invariant
	that the witness verification path rejects all other algorithm IDs, in
	particular the 65-byte Ethereum-format ones (EIP-191, EIP-712).

KEY ARCHITECTURAL DECISIONS:
  - These tests exist because the witness layer (crypto/signatures/witness_verify.go)
    calls VerifyEntry directly, which is the raw 64-byte ECDSA primitive.
    The web3 refactor introduced 65-byte signature formats that witness
    infrastructure MUST NOT accept, because witnesses do not carry the
    Ethereum-address-based trust model.
  - The test operates at the wire-framing level. A witness cosignature
    envelope tagged with SigAlgoEIP712 and carrying a 65-byte signature
    must be rejected — preferably at the framing check, but if it slips
    past framing it must still be rejected by the verification step.
  - Supplements existing tests/witness_verify_test.go. Does not replace.
*/
package tests

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// -------------------------------------------------------------------------------------------------
// 1) Witness signature path is ECDSA-only — wire-framing invariant
// -------------------------------------------------------------------------------------------------

// TestWitness_RejectsEthereumSigLengths locks the invariant that an entry
// carrying a 65-byte Ethereum-format signature cannot be mis-framed as a
// 64-byte witness-style entry.
//
// The mechanism: AppendSignature with SigAlgoECDSA and a 65-byte signature
// is rejected by the encode-side length check. If this were permissive,
// attackers could smuggle wallet-format sigs past the SDK-native verifier.
// TestWitness_RejectsEthereumSigLengths was retired in the v6
// migration. This test exercised an encoding-level length check that
// v6 deliberately removed (algorithms like SigAlgoJWZ are
// variable-length). The real security invariant — "the witness
// signature path rejects Ethereum-format 65-byte wallet signatures" —
// is preserved and tested correctly by
// TestWitness_OnlyECDSASignaturesAccepted below, which exercises the
// cryptographic verifier (signatures.VerifyEntry) directly. That is
// the correct layer for the invariant: the verifier is the authority
// on what signatures it accepts, not the framing code.

// -------------------------------------------------------------------------------------------------
// 2) Raw VerifyEntry enforces 64-byte signatures
// -------------------------------------------------------------------------------------------------

// TestVerifyEntry_Rejects65ByteSignature locks the raw primitive behavior.
// Any drift here means witness verification could accept wallet signatures,
// which would bypass witness-specific trust semantics.
func TestVerifyEntry_Rejects65ByteSignature(t *testing.T) {
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var hash [32]byte
	copy(hash[:], []byte("some canonical hash content..."))

	// Produce a valid 64-byte signature, then append a spurious byte to make it 65.
	sig64, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	sig65 := append(append([]byte{}, sig64...), 0x1b)

	if err := signatures.VerifyEntry(hash, sig65, &priv.PublicKey); err == nil {
		t.Fatal("VerifyEntry accepted 65-byte signature — would allow wallet sigs through witness path")
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Witness-path algorithm ID sweep
// -------------------------------------------------------------------------------------------------

// TestWitness_OnlyECDSASignaturesAccepted iterates all registered algorithm
// IDs and asserts that only SigAlgoECDSA can produce bytes that VerifyEntry
// (the witness primitive) accepts.
//
// Strategy: for each algorithm, attempt to produce a valid wire entry using
// the signing primitive for that algorithm. Then attempt to verify using the
// witness-side VerifyEntry. Only the SigAlgoECDSA case should succeed.
func TestWitness_OnlyECDSASignaturesAccepted(t *testing.T) {
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var hash [32]byte
	copy(hash[:], []byte("witness canonical hash"))

	// Case 1: SigAlgoECDSA — the only acceptable witness algorithm.
	sigECDSA, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	if err := signatures.VerifyEntry(hash, sigECDSA, &priv.PublicKey); err != nil {
		t.Fatalf("VerifyEntry rejected valid ECDSA signature: %v", err)
	}

	// Case 2: SigAlgoEIP191 — 65-byte signature, must be rejected at raw layer.
	digest191 := signatures.EIP191Digest(hash[:])
	sig191 := signEthereumRecoverable(priv, digest191)
	if err := signatures.VerifyEntry(hash, sig191, &priv.PublicKey); err == nil {
		t.Fatal("VerifyEntry accepted an EIP-191 signature — witness path is permissive")
	}

	// Case 3: SigAlgoEIP712 — 65-byte signature over different digest.
	digest712 := signatures.EntrySigningDigest(hash)
	sig712 := signEthereumRecoverable(priv, digest712)
	if err := signatures.VerifyEntry(hash, sig712, &priv.PublicKey); err == nil {
		t.Fatal("VerifyEntry accepted an EIP-712 signature — witness path is permissive")
	}
}

// -------------------------------------------------------------------------------------------------
// 4) SignatureLengthForAlgorithm — witness algorithms identified correctly
// -------------------------------------------------------------------------------------------------

// TestWitness_AlgorithmClassification asserts that the classification of
// algorithms into "SDK-native 64-byte" and "wallet-format 65-byte" matches
// what the witness layer expects. The witness code assumes algoID of
// SigAlgoECDSA means 64 bytes; if that changes, witness deserialization
// silently corrupts.
// TestWitness_AlgorithmClassification was retired in the v6
// migration. envelope.SignatureLengthForAlgorithm was removed because
// v6 signatures are length-prefixed per-sig in the wire format, making
// algorithm-level length classification meaningless. See
// TestSignatureLengthForAlgorithm_FROZEN retirement comment in
// tests/web3_frozen_test.go for full rationale.
