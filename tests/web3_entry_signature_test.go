/*
FILE PATH:

	tests/web3_entry_signature_test.go

DESCRIPTION:

	Round-trip tests for entry signing across all four registered algorithms,
	and the critical invariant that the canonical hash is independent of
	which algorithm signed the entry.

KEY ARCHITECTURAL DECISIONS:
  - Each algorithm gets its own round-trip test. No table-driven collapse
    here — the failure messages need to point precisely to the broken path.
  - The canonical-hash invariance test is the most important test in this
    file. If the algorithm ID influences the canonical hash, wallet-signed
    entries would have different log identities than SDK-signed entries.
    That would fragment the log across signer types — a protocol-level
    disaster.
  - Tests #1-#4 were simplified in the v6 migration — the wire round-trip
    through AppendSignature/StripSignature (both deleted in v6) was
    boilerplate. The primitive-level verifier call is the actual assertion.
  - Tests #5 and #6 were restated in the v6 migration at the Serialize /
    SigningPayload level rather than the AppendSignature / StripSignature
    level. The underlying invariants are unchanged; the surface they are
    expressed against is the v6-native one.
  - Supplements existing tests/entry_signature_test.go. Does not replace.
*/
package tests

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// -------------------------------------------------------------------------------------------------
// 1) ECDSA secp256k1 raw — SDK-native signers
// -------------------------------------------------------------------------------------------------

func TestEntrySignature_RoundTrip_ECDSA(t *testing.T) {
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var canonicalHash [32]byte
	copy(canonicalHash[:], []byte("canonical-entry-content-32bytes!"))

	sig, err := signatures.SignEntry(canonicalHash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("SignEntry produced %d bytes, want 64", len(sig))
	}

	// Signature verifies against the key. Under v6 the wire round-trip
	// through AppendSignature/StripSignature no longer exists; the
	// primitive-level verifier call IS the assertion of interest here.
	if err := signatures.VerifyEntry(canonicalHash, sig, &priv.PublicKey); err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 2) Ed25519 — non-EVM native keys
// -------------------------------------------------------------------------------------------------

func TestEntrySignature_RoundTrip_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 GenerateKey: %v", err)
	}

	// Ed25519 signs the full message, not a hash. Pick a realistic message.
	message := []byte("canonical entry bytes representing a full Ortholog entry")
	sig := ed25519.Sign(priv, message)
	if len(sig) != 64 {
		t.Fatalf("ed25519 sig length %d, want 64", len(sig))
	}

	// Signature verifies. Under v6 the wire round-trip no longer exists;
	// the primitive-level verifier is the assertion of interest.
	if err := signatures.VerifyEd25519(pub, message, sig); err != nil {
		t.Fatalf("VerifyEd25519: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 3) EIP-191 — wallet personal_sign
// -------------------------------------------------------------------------------------------------

func TestEntrySignature_RoundTrip_EIP191(t *testing.T) {
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
	copy(canonicalHash[:], []byte("canonical-entry-hash-for-eip191!"))

	// Simulate wallet: sign the EIP-191 digest over canonical hash.
	digest := signatures.EIP191Digest(canonicalHash[:])
	sig := signEthereumRecoverable(priv, digest)
	if len(sig) != 65 {
		t.Fatalf("recoverable sig length %d, want 65", len(sig))
	}

	// Verify via address recovery. Under v6 the wire round-trip no longer
	// exists; the primitive-level verifier is the assertion of interest.
	if err := signatures.VerifySecp256k1EIP191(addr, canonicalHash, sig); err != nil {
		t.Fatalf("VerifySecp256k1EIP191: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) EIP-712 — wallet signTypedData_v4
// -------------------------------------------------------------------------------------------------

func TestEntrySignature_RoundTrip_EIP712(t *testing.T) {
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
	copy(canonicalHash[:], []byte("canonical-entry-hash-for-eip712!"))

	// Simulate wallet: sign the EIP-712 typed-data digest committing to canonical hash.
	digest := signatures.EntrySigningDigest(canonicalHash)
	sig := signEthereumRecoverable(priv, digest)

	// Verify via address recovery. Under v6 the wire round-trip no longer
	// exists; the primitive-level verifier is the assertion of interest.
	if err := signatures.VerifySecp256k1EIP712(addr, canonicalHash, sig); err != nil {
		t.Fatalf("VerifySecp256k1EIP712: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 5) Canonical hash invariance across algorithm IDs — THE critical invariant
// -------------------------------------------------------------------------------------------------

// TestEntrySignature_CanonicalHashIndependentOfAlgoID verifies that the
// SigningPayload of an entry does not depend on which algorithm signed
// it. The v5 version of this test used AppendSignature/StripSignature
// over raw canonical bytes; v6 restates it at the entry level using
// envelope.SigningPayload, which is what every signer actually signs.
//
// If this test fails, two signers using the same header and payload
// but different algorithms would sign over different byte sequences,
// producing signatures that commit to different content. That would
// fragment the log across signer types — the protocol-level disaster
// the v5 test was protecting against.
func TestEntrySignature_CanonicalHashIndependentOfAlgoID(t *testing.T) {
	// Same header, same payload, different algoIDs in the Signatures
	// slice. SigningPayload must be byte-identical for all.
	header := envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:canonical-test",
	}
	payload := []byte("the exact same canonical entry content")

	algorithms := []uint16{
		envelope.SigAlgoECDSA,
		envelope.SigAlgoEd25519,
		envelope.SigAlgoEIP191,
		envelope.SigAlgoEIP712,
		envelope.SigAlgoJWZ,
	}

	var payloads [][]byte
	for _, algoID := range algorithms {
		entry, err := envelope.NewUnsignedEntry(header, payload)
		if err != nil {
			t.Fatalf("NewUnsignedEntry(algo 0x%04x): %v", algoID, err)
		}
		// Attach a signature with this algoID. SigningPayload must not
		// depend on what's in Signatures — that's the invariant.
		sigLen := 64
		if algoID == envelope.SigAlgoEIP191 || algoID == envelope.SigAlgoEIP712 {
			sigLen = 65
		} else if algoID == envelope.SigAlgoJWZ {
			sigLen = 512
		}
		entry.Signatures = []envelope.Signature{{
			SignerDID: header.SignerDID,
			AlgoID:    algoID,
			Bytes:     make([]byte, sigLen),
		}}
		payloads = append(payloads, envelope.SigningPayload(entry))
	}

	// All SigningPayloads must be byte-identical.
	for i := 1; i < len(payloads); i++ {
		if !bytes.Equal(payloads[0], payloads[i]) {
			t.Fatalf("SigningPayload drift between algo 0x%04x and algo 0x%04x:\n[0]: %x\n[%d]: %x",
				algorithms[0], algorithms[i], payloads[0], i, payloads[i])
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 6) Wire-length arithmetic — canonical length unchanged by sig length
// -------------------------------------------------------------------------------------------------

// TestEntrySignature_WireLengthArithmetic asserts that the difference in
// total Serialize output between a 64-byte-sig entry and a 65-byte-sig
// entry (with identical header, payload, and SignerDID on the
// signature) is EXACTLY 1 byte. Under v6 this holds because the
// sig length prefix is a fixed-width uint32; only the sig bytes
// themselves differ in length.
//
// Any other delta indicates a variable-width encoding snuck in
// somewhere — a wire-format regression.
func TestEntrySignature_WireLengthArithmetic(t *testing.T) {
	const signerDID = "did:example:wire-arithmetic"
	header := envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   signerDID,
	}
	payload := []byte("payload")

	build := func(algoID uint16, sigLen int) []byte {
		entry, err := envelope.NewUnsignedEntry(header, payload)
		if err != nil {
			t.Fatalf("NewUnsignedEntry: %v", err)
		}
		entry.Signatures = []envelope.Signature{{
			SignerDID: signerDID,
			AlgoID:    algoID,
			Bytes:     make([]byte, sigLen),
		}}
		return envelope.Serialize(entry)
	}

	w64 := build(envelope.SigAlgoECDSA, 64)
	w65 := build(envelope.SigAlgoEIP712, 65)

	if len(w65)-len(w64) != 1 {
		t.Fatalf("wire length delta between 65-byte and 64-byte sigs is %d, expected exactly 1",
			len(w65)-len(w64))
	}
}
