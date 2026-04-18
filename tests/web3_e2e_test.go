/*
FILE PATH:
    tests/web3_e2e_test.go

DESCRIPTION:
    End-to-end tests for each (DID method × signature algorithm) combination
    the protocol supports. Each test exercises the full stack:
        DID construction
          -> canonical hash
          -> sign with algorithm-specific primitive
          -> envelope.AppendSignature
          -> envelope.StripSignature
          -> registry.Verify dispatches to method-specific verifier
          -> verifier performs primitive-level verification
    Any broken wiring fails here, regardless of whether per-verifier unit
    tests pass in isolation.

KEY ARCHITECTURAL DECISIONS:
  - One test function per (method, algorithm) combination. Named tests keep
    CI failure output pinpoint-precise.
  - Tests use a panicResolver for did:pkh and did:key (neither should touch
    the web resolver). A staticResolver is used for did:web tests.
  - Every test follows the same four-step template:
        1. Produce keypair / DID
        2. Sign canonical hash
        3. Round-trip through envelope framing
        4. Verify via the registry
    Any deviation from this template indicates the test is measuring
    something other than end-to-end behavior.
*/
package tests

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// -------------------------------------------------------------------------------------------------
// 1) E2E — did:key + Ed25519 + SigAlgoEd25519
// -------------------------------------------------------------------------------------------------

func TestE2E_DIDKey_Ed25519(t *testing.T) {
	kp, err := did.GenerateDIDKeyEd25519()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	message := []byte("canonical entry content for did:key Ed25519")
	sig := ed25519.Sign(kp.PrivateKey, message)

	// Wire round-trip
	wire, err := envelope.AppendSignature(message, envelope.SigAlgoEd25519, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}
	if !bytes.Equal(gotCanon, message) || gotAlgo != envelope.SigAlgoEd25519 {
		t.Fatal("wire round-trip mismatch")
	}

	// Verify via registry
	registry := newTestRegistry(t)
	if err := registry.Verify(kp.DID, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 2) E2E — did:key + secp256k1 + SigAlgoECDSA
// -------------------------------------------------------------------------------------------------

func TestE2E_DIDKey_Secp256k1_ECDSA(t *testing.T) {
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var canonicalHash [32]byte
	copy(canonicalHash[:], []byte("did:key secp256k1 canonical hash"))

	sig, err := signatures.SignEntry(canonicalHash, kp.PrivateKey)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}

	// Wire round-trip
	wire, err := envelope.AppendSignature(canonicalHash[:], envelope.SigAlgoECDSA, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}

	registry := newTestRegistry(t)
	if err := registry.Verify(kp.DID, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 3) E2E — did:key + P-256 + SigAlgoECDSA
// -------------------------------------------------------------------------------------------------

func TestE2E_DIDKey_P256_ECDSA(t *testing.T) {
	kp, err := did.GenerateDIDKeyP256()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var canonicalHash [32]byte
	copy(canonicalHash[:], []byte("did:key P-256 canonical hash...."))

	// SignEntry is curve-agnostic — uses the curve of the provided key.
	sig, err := signatures.SignEntry(canonicalHash, kp.PrivateKey)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}

	wire, err := envelope.AppendSignature(canonicalHash[:], envelope.SigAlgoECDSA, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}

	registry := newTestRegistry(t)
	if err := registry.Verify(kp.DID, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) (intentionally empty — raw SigAlgoECDSA + did:pkh cannot be wire-framed)
// -------------------------------------------------------------------------------------------------
//
// did:pkh verification requires 65-byte Ethereum-format signatures (r||s||v)
// because it performs ecrecover. The wire framing ties SigAlgoECDSA to the
// 64-byte raw (R||S) format used by SDK-native signers. The two do not
// compose on the wire: a 65-byte sig cannot be AppendSignature'd as
// SigAlgoECDSA. Therefore every did:pkh E2E path goes through SigAlgoEIP191
// or SigAlgoEIP712 — covered by the two tests below.

// -------------------------------------------------------------------------------------------------
// 5) E2E — did:pkh + EIP-191 (wallet personal_sign)
// -------------------------------------------------------------------------------------------------

func TestE2E_DIDPKH_EIP191(t *testing.T) {
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	didStr, _ := didPKHForKey(t, priv)

	var canonicalHash [32]byte
	copy(canonicalHash[:], []byte("did:pkh EIP-191 canonical hash."))

	// Simulate wallet personal_sign: wallet signs EIP191Digest(canonical).
	digest := signatures.EIP191Digest(canonicalHash[:])
	sig := signEthereumRecoverable(priv, digest)

	wire, err := envelope.AppendSignature(canonicalHash[:], envelope.SigAlgoEIP191, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}

	registry := newTestRegistry(t)
	if err := registry.Verify(didStr, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 6) E2E — did:pkh + EIP-712 (wallet signTypedData_v4)
// -------------------------------------------------------------------------------------------------

func TestE2E_DIDPKH_EIP712(t *testing.T) {
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	didStr, _ := didPKHForKey(t, priv)

	var canonicalHash [32]byte
	copy(canonicalHash[:], []byte("did:pkh EIP-712 canonical hash."))

	// Simulate wallet signTypedData_v4: wallet signs the Ortholog entry
	// typed-data digest committing to canonical hash.
	digest := signatures.EntrySigningDigest(canonicalHash)
	sig := signEthereumRecoverable(priv, digest)

	wire, err := envelope.AppendSignature(canonicalHash[:], envelope.SigAlgoEIP712, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}

	registry := newTestRegistry(t)
	if err := registry.Verify(didStr, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 7) E2E — did:web + secp256k1 + SigAlgoECDSA
// -------------------------------------------------------------------------------------------------

func TestE2E_DIDWeb_Secp256k1_ECDSA(t *testing.T) {
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubUncompressed := signatures.PubKeyBytes(&priv.PublicKey)
	pubCompressed, err := signatures.CompressSecp256k1Pubkey(pubUncompressed)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}

	var canonicalHash [32]byte
	copy(canonicalHash[:], []byte("did:web secp256k1 canonical...."))
	sig, err := signatures.SignEntry(canonicalHash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}

	const didStr = "did:web:operator.example.com"
	doc := &did.DIDDocument{
		ID: didStr,
		VerificationMethod: []did.VerificationMethod{
			{
				ID:           didStr + "#key-0",
				Type:         did.VerificationMethodSecp256k1,
				Controller:   didStr,
				PublicKeyHex: hex.EncodeToString(pubCompressed),
			},
		},
	}

	wire, err := envelope.AppendSignature(canonicalHash[:], envelope.SigAlgoECDSA, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}

	resolver := &staticResolver{wantDID: didStr, doc: doc}
	registry := did.DefaultVerifierRegistry(resolver)

	if err := registry.Verify(didStr, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 8) E2E — did:web + Ed25519 + SigAlgoEd25519
// -------------------------------------------------------------------------------------------------

func TestE2E_DIDWeb_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	message := []byte("did:web Ed25519 canonical content")
	sig := ed25519.Sign(priv, message)

	const didStr = "did:web:ed25519.example.com"
	doc := &did.DIDDocument{
		ID: didStr,
		VerificationMethod: []did.VerificationMethod{
			{
				ID:           didStr + "#key-0",
				Type:         did.VerificationMethodEd25519,
				Controller:   didStr,
				PublicKeyHex: hex.EncodeToString(pub),
			},
		},
	}

	wire, err := envelope.AppendSignature(message, envelope.SigAlgoEd25519, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}

	resolver := &staticResolver{wantDID: didStr, doc: doc}
	registry := did.DefaultVerifierRegistry(resolver)

	if err := registry.Verify(didStr, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 9) E2E — did:web + secp256k1 recovery (EIP-712 against address-only VM)
// -------------------------------------------------------------------------------------------------

// TestE2E_DIDWeb_RecoveryMethod exercises the did:web variant where the
// verification method is an EcdsaSecp256k1RecoveryMethod2020 carrying only
// the 20-byte Ethereum address. The web verifier routes these through
// ecrecover rather than pubkey verification, matching the did:pkh semantics.
func TestE2E_DIDWeb_RecoveryMethod(t *testing.T) {
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := signatures.PubKeyBytes(&priv.PublicKey)
	addr, err := signatures.AddressFromPubkey(pub)
	if err != nil {
		t.Fatalf("AddressFromPubkey: %v", err)
	}

	var canonicalHash [32]byte
	copy(canonicalHash[:], []byte("did:web recovery+EIP-712 canon."))

	digest := signatures.EntrySigningDigest(canonicalHash)
	sig := signEthereumRecoverable(priv, digest)

	const didStr = "did:web:recovery.example.com"
	doc := &did.DIDDocument{
		ID: didStr,
		VerificationMethod: []did.VerificationMethod{
			{
				ID:                  didStr + "#recovery",
				Type:                did.VerificationMethodSecp256k1Recovery,
				Controller:          didStr,
				BlockchainAccountID: "eip155:1:0x" + hex.EncodeToString(addr[:]),
			},
		},
	}

	wire, err := envelope.AppendSignature(canonicalHash[:], envelope.SigAlgoEIP712, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}

	resolver := &staticResolver{wantDID: didStr, doc: doc}
	registry := did.DefaultVerifierRegistry(resolver)

	if err := registry.Verify(didStr, gotCanon, gotSig, gotAlgo); err != nil {
		t.Fatalf("registry.Verify: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 10) E2E — unregistered DID method routes to ErrVerifierNotRegistered
// -------------------------------------------------------------------------------------------------

// TestE2E_UnregisteredMethod_Rejected locks the dispatch fail-loud contract.
// A DID with a method the registry doesn't know about MUST NOT be silently
// accepted or routed to a default verifier.
func TestE2E_UnregisteredMethod_Rejected(t *testing.T) {
	registry := newTestRegistry(t)

	err := registry.Verify(
		"did:ethr:0xabcdef0123456789abcdef0123456789abcdef01",
		make([]byte, 32),
		make([]byte, 65),
		envelope.SigAlgoEIP712,
	)
	if err == nil {
		t.Fatal("unregistered method accepted")
	}
}

// -------------------------------------------------------------------------------------------------
// 11) E2E — cross-method-method tampering: sig against wrong DID type fails
// -------------------------------------------------------------------------------------------------

// TestE2E_CrossMethodTampering_Rejected asserts that a signature produced
// for did:key cannot be replayed against a did:pkh with the same underlying
// keypair. The two methods enforce different verification semantics, and
// accepting a sig across methods would be a protocol violation.
func TestE2E_CrossMethodTampering_Rejected(t *testing.T) {
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
	}

	// Produce a 64-byte raw ECDSA signature — valid for did:key.
	var canonicalHash [32]byte
	copy(canonicalHash[:], []byte("cross-method tampering test...."))
	sig64, err := signatures.SignEntry(canonicalHash, kp.PrivateKey)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}

	// Build the did:pkh that would correspond to the SAME keypair.
	pkhDID, _ := didPKHForKey(t, kp.PrivateKey)

	registry := newTestRegistry(t)

	// 64-byte sig against did:pkh must fail — did:pkh expects 65 bytes.
	err = registry.Verify(pkhDID, canonicalHash[:], sig64, envelope.SigAlgoECDSA)
	if err == nil {
		t.Fatal("64-byte sig accepted against did:pkh — cross-method replay would be possible")
	}
}

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

// newTestRegistry builds a VerifierRegistry with a panicResolver, suitable
// for did:pkh and did:key tests that must not consult the web resolver.
// did:web tests construct their own registry with a static resolver.
func newTestRegistry(t *testing.T) *did.VerifierRegistry {
	t.Helper()
	return did.DefaultVerifierRegistry(panicResolver{t: t})
}
