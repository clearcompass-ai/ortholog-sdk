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

	// Wire round-trip
	canonical := []byte("canonical bytes")
	wire, err := envelope.AppendSignature(canonical, envelope.SigAlgoECDSA, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}
	if !bytes.Equal(gotCanon, canonical) || gotAlgo != envelope.SigAlgoECDSA || !bytes.Equal(gotSig, sig) {
		t.Fatal("wire round-trip mismatch")
	}

	// Signature verifies against the key
	if err := signatures.VerifyEntry(canonicalHash, gotSig, &priv.PublicKey); err != nil {
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

	// Wire round-trip
	wire, err := envelope.AppendSignature(message, envelope.SigAlgoEd25519, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	gotCanon, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}
	if !bytes.Equal(gotCanon, message) || gotAlgo != envelope.SigAlgoEd25519 || !bytes.Equal(gotSig, sig) {
		t.Fatal("wire round-trip mismatch")
	}

	// Signature verifies
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

	// Wire round-trip
	canonical := []byte("canonical bytes")
	wire, err := envelope.AppendSignature(canonical, envelope.SigAlgoEIP191, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	_, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}
	if gotAlgo != envelope.SigAlgoEIP191 || len(gotSig) != 65 {
		t.Fatal("wire round-trip mismatch")
	}

	// Verify via address recovery
	if err := signatures.VerifySecp256k1EIP191(addr, canonicalHash, gotSig); err != nil {
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

	// Wire round-trip
	canonical := []byte("canonical bytes")
	wire, err := envelope.AppendSignature(canonical, envelope.SigAlgoEIP712, sig)
	if err != nil {
		t.Fatalf("AppendSignature: %v", err)
	}
	_, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatalf("StripSignature: %v", err)
	}
	if gotAlgo != envelope.SigAlgoEIP712 {
		t.Fatalf("StripSignature algoID mismatch: got 0x%04x", gotAlgo)
	}

	// Verify via address recovery
	if err := signatures.VerifySecp256k1EIP712(addr, canonicalHash, gotSig); err != nil {
		t.Fatalf("VerifySecp256k1EIP712: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 5) Canonical hash invariance across algorithm IDs — THE critical invariant
// -------------------------------------------------------------------------------------------------

// TestEntrySignature_CanonicalHashIndependentOfAlgoID verifies that the
// canonical bytes of an entry do not depend on which algorithm signed it.
//
// If this test fails, two signers using the same entry content but different
// algorithms would produce entries with different canonical hashes, which
// means different log identities, which fragments the log across signer
// types. This is the kind of invariant that silently rots if not locked.
func TestEntrySignature_CanonicalHashIndependentOfAlgoID(t *testing.T) {
	// Same canonical bytes, four different algorithms.
	canonical := []byte("the exact same canonical entry content")

	algorithms := []struct {
		id  uint16
		sig []byte
	}{
		{envelope.SigAlgoECDSA, make([]byte, 64)},
		{envelope.SigAlgoEd25519, make([]byte, 64)},
		{envelope.SigAlgoEIP191, make([]byte, 65)},
		{envelope.SigAlgoEIP712, make([]byte, 65)},
	}

	var wires [][]byte
	for _, a := range algorithms {
		w, err := envelope.AppendSignature(canonical, a.id, a.sig)
		if err != nil {
			t.Fatalf("AppendSignature(0x%04x): %v", a.id, err)
		}
		wires = append(wires, w)
	}

	// Each wire, when stripped, must yield the IDENTICAL canonical bytes.
	for i, wire := range wires {
		gotCanon, gotAlgo, _, err := envelope.StripSignature(wire)
		if err != nil {
			t.Fatalf("wire %d (algo 0x%04x): StripSignature: %v", i, algorithms[i].id, err)
		}
		if !bytes.Equal(gotCanon, canonical) {
			t.Fatalf("wire %d (algo 0x%04x): canonical drifted\noriginal: %x\ngot:      %x",
				i, algorithms[i].id, canonical, gotCanon)
		}
		if gotAlgo != algorithms[i].id {
			t.Fatalf("wire %d: algoID roundtrip drifted", i)
		}
	}

	// The four wires MUST differ from each other — they carry different
	// signatures and algo IDs. But the canonical prefix of each is identical.
	for i := 0; i < len(wires); i++ {
		for j := i + 1; j < len(wires); j++ {
			if bytes.Equal(wires[i], wires[j]) {
				t.Fatalf("wires %d and %d identical — algo ID not encoded distinctly", i, j)
			}
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 6) Wire-length arithmetic — canonical length unchanged by sig length
// -------------------------------------------------------------------------------------------------

// TestEntrySignature_WireLengthArithmetic asserts that the difference in
// total wire length between a 64-byte-sig entry and a 65-byte-sig entry
// is EXACTLY 1 byte. Any other delta indicates a variable-width encoding
// snuck in somewhere.
func TestEntrySignature_WireLengthArithmetic(t *testing.T) {
	canonical := []byte("canonical")

	w64, err := envelope.AppendSignature(canonical, envelope.SigAlgoECDSA, make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	w65, err := envelope.AppendSignature(canonical, envelope.SigAlgoEIP712, make([]byte, 65))
	if err != nil {
		t.Fatal(err)
	}

	if len(w65)-len(w64) != 1 {
		t.Fatalf("wire length delta between 65-byte and 64-byte sigs is %d, expected exactly 1",
			len(w65)-len(w64))
	}
}
