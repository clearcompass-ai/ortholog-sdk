// Package envelope — serialize_binding_test.go holds the binding
// tests for the four mutation-audit switches in
// serialize_mutation_switches.go. See
// core/envelope/serialize.mutation-audit.yaml for the registry.
package envelope

import (
	"errors"
	"testing"
)

// validHeader returns a minimally-valid ControlHeader for binding
// tests that need a real entry to round-trip through Serialize.
func validHeader() ControlHeader {
	return ControlHeader{
		SignerDID:   "did:web:example.com:signer",
		Destination: "did:web:example.com:exchange",
	}
}

// validSig returns a 64-byte zero-ECDSA signature attached to the
// given signer DID. Adequate for tests that only exercise structural
// invariants — Validate() does not perform cryptographic verification.
func validSig(signerDID string) Signature {
	return Signature{
		SignerDID: signerDID,
		AlgoID:    SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableDestinationBound
// ─────────────────────────────────────────────────────────────────────

// TestValidateHeader_RejectsEmptyDestination_Binding pins that
// validateHeaderForWrite rejects an entry with an empty destination
// — the canonical-hash destination-binding property fails the
// moment this validation is bypassed.
func TestValidateHeader_RejectsEmptyDestination_Binding(t *testing.T) {
	h := validHeader()
	h.Destination = "" // empty
	_, err := NewUnsignedEntry(h, []byte("payload"))
	if err == nil {
		t.Fatal("NewUnsignedEntry accepted empty Destination (muEnableDestinationBound not load-bearing?)")
	}
	if !errors.Is(err, ErrDestinationEmpty) {
		t.Fatalf("want ErrDestinationEmpty, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableSizeCap
// ─────────────────────────────────────────────────────────────────────

// TestDeserialize_RejectsOversize_Binding pins that Deserialize
// rejects a buffer exceeding MaxCanonicalBytes with
// ErrCanonicalTooLarge. With the gate off, oversize buffers fall
// through to header parsing where they hit a different error or
// silently succeed depending on internal layout.
func TestDeserialize_RejectsOversize_Binding(t *testing.T) {
	oversized := make([]byte, MaxCanonicalBytes+1)
	_, err := Deserialize(oversized)
	if !errors.Is(err, ErrCanonicalTooLarge) {
		t.Fatalf("want ErrCanonicalTooLarge, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableVersionReject
// ─────────────────────────────────────────────────────────────────────

// TestDeserialize_RejectsUnsupportedVersion_Binding pins that
// Deserialize rejects an entry whose protocol version is not
// readable. Construction: build a valid entry, then flip the
// 2-byte version preamble to a clearly-unsupported value
// (0xFFFE) so the rest of the canonical bytes remain
// well-formed. With the gate on, CheckReadAllowed rejects
// before any header parsing. With the gate off, the version
// check is skipped and the rest of the buffer parses cleanly
// (header, payload, signatures all valid) — silent
// forward-incompatibility.
func TestDeserialize_RejectsUnsupportedVersion_Binding(t *testing.T) {
	h := validHeader()
	entry, err := NewUnsignedEntry(h, []byte("test"))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []Signature{validSig(h.SignerDID)}
	if err := entry.Validate(); err != nil {
		t.Fatalf("entry.Validate: %v", err)
	}
	canonical := Serialize(entry)
	// Corrupt the version preamble in place.
	canonical[0] = 0xFF
	canonical[1] = 0xFE

	_, err = Deserialize(canonical)
	if err == nil {
		t.Fatal("Deserialize accepted version 0xFFFE (muEnableVersionReject not load-bearing?)")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableCanonicalOrdering
// ─────────────────────────────────────────────────────────────────────

// TestDeserialize_RejectsTrailingBytes_Binding pins that
// ReadSignaturesSection rejects trailing bytes after the declared
// signatures count. With the gate off, trailing bytes are
// accepted and two distinct buffers deserialize to the same Entry
// — breaking the canonical-form contract.
//
// Construction: serialize a valid entry, append a single trailing
// byte to the canonical bytes, attempt Deserialize. The gate-on
// path returns ErrTrailingBytes; the gate-off path silently
// succeeds.
func TestDeserialize_RejectsTrailingBytes_Binding(t *testing.T) {
	h := validHeader()
	entry, err := NewUnsignedEntry(h, []byte("test payload"))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []Signature{validSig(h.SignerDID)}
	if err := entry.Validate(); err != nil {
		t.Fatalf("entry.Validate: %v", err)
	}
	canonical := Serialize(entry)
	// Append a single trailing byte.
	tampered := append(canonical, 0xAA)

	_, err = Deserialize(tampered)
	if err == nil {
		t.Fatal("Deserialize accepted trailing-byte buffer (muEnableCanonicalOrdering not load-bearing?)")
	}
	if !errors.Is(err, ErrTrailingBytes) {
		t.Fatalf("want ErrTrailingBytes, got %v", err)
	}
}
