// Package tests — tessera_compat_test.go locks the SDK's Tessera-compat
// primitives (EntryIdentity, EntryLeafHash, MarshalBundleEntry, BundleEntries)
// against their published specifications:
//
//   - RFC 6962 §2.1 (leaf hash domain separation)
//   - c2sp.org/tlog-tiles (bundle entry framing)
//   - Tessera's Entry contract (identity = SHA-256 of data)
//
// The test suite does NOT import Tessera itself. We verify the SDK's output
// against the specs directly. If Tessera ever drifts from these specs (it
// won't — they're frozen), the SDK remains correct by construction.
//
// If you want a belt-and-suspenders integration test that imports Tessera
// and asserts the SDK's LeafHash == tessera.NewEntry(data).LeafHash(), add
// a separate file tessera_integration_test.go behind a build tag — it
// pulls Tessera as a test-only dependency.
package tests

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// 1. EntryIdentity — matches SHA-256(serialize(entry))
// ─────────────────────────────────────────────────────────────────────

// TestEntryIdentity_MatchesSHA256 asserts that EntryIdentity produces
// exactly SHA-256(Serialize(entry)). This is Tessera's identityHash
// contract and the dedup key contract simultaneously.
func TestEntryIdentity_MatchesSHA256(t *testing.T) {
	entry := buildTestEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:identity",
	}, []byte("payload"))

	got := envelope.EntryIdentity(entry)
	want := sha256.Sum256(envelope.Serialize(entry))

	if got != want {
		t.Fatalf("EntryIdentity = %x, want SHA-256(Serialize(entry)) = %x", got, want)
	}
}

// TestEntryIdentity_Deterministic asserts that two independently
// constructed entries with identical fields produce identical identities.
// This is the dedup-key invariant.
func TestEntryIdentity_Deterministic(t *testing.T) {
	header := envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:determinism",
		EventTime:   1_700_000_000,
	}
	e1 := buildTestEntry(t, header, []byte("same"))
	e2 := buildTestEntry(t, header, []byte("same"))

	if envelope.EntryIdentity(e1) != envelope.EntryIdentity(e2) {
		t.Fatal("EntryIdentity must be deterministic for structurally equal entries")
	}
}

// TestEntryIdentity_Distinguishes asserts that structurally different
// entries produce different identities. The destination-binding property
// makes this test especially meaningful: two entries that differ ONLY in
// Destination must have different identities.
func TestEntryIdentity_Distinguishes(t *testing.T) {
	e1 := buildTestEntry(t, envelope.ControlHeader{
		Destination: "did:web:exchange-A.example",
		SignerDID:   "did:example:signer",
	}, []byte("payload"))
	e2 := buildTestEntry(t, envelope.ControlHeader{
		Destination: "did:web:exchange-B.example",
		SignerDID:   "did:example:signer",
	}, []byte("payload"))

	if envelope.EntryIdentity(e1) == envelope.EntryIdentity(e2) {
		t.Fatal("entries with different destinations must produce different identities")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 2. EntryLeafHash — matches RFC 6962 §2.1 exactly
// ─────────────────────────────────────────────────────────────────────

// TestEntryLeafHash_MatchesRFC6962 asserts that EntryLeafHash produces
// exactly SHA-256(0x00 || Serialize(entry)). This is the RFC 6962 leaf
// hash rule, frozen by the spec since 2013.
func TestEntryLeafHash_MatchesRFC6962(t *testing.T) {
	entry := buildTestEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:leafhash",
	}, []byte("payload"))

	data := envelope.Serialize(entry)

	// Compute RFC 6962 leaf hash the spec way.
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var want [32]byte
	copy(want[:], h.Sum(nil))

	got := envelope.EntryLeafHash(entry)

	if got != want {
		t.Fatalf("EntryLeafHash = %x, want RFC-6962 leaf hash = %x", got, want)
	}
}

// TestEntryLeafHash_DistinctFromIdentity asserts that LeafHash != Identity.
// This is the whole point of domain separation: the same underlying bytes
// produce different hashes depending on their role (dedup vs tree leaf).
//
// If this test ever passes with equality, either:
//
//	(a) the RFC 6962 prefix byte was silently removed, or
//	(b) something is double-hashing, or
//	(c) someone replaced LeafHash with Identity's implementation
//
// Any of the three is a severe bug — merkle proofs against the tree
// head would systematically fail in subtle ways.
func TestEntryLeafHash_DistinctFromIdentity(t *testing.T) {
	entry := buildTestEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:domainsep",
	}, []byte("payload"))

	if envelope.EntryLeafHash(entry) == envelope.EntryIdentity(entry) {
		t.Fatal("LeafHash and Identity must differ — RFC 6962 domain separation lost")
	}
}

// TestEntryLeafHash_EmptyPayload pins the leaf hash for an
// empty-payload entry. Empty-payload entries (commentary, cosignatures)
// are common in the protocol; their leaf hashes must be computed
// consistently.
func TestEntryLeafHash_EmptyPayload(t *testing.T) {
	entry := buildTestEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:empty",
	}, nil)

	data := envelope.Serialize(entry)
	if len(data) == 0 {
		t.Fatal("Serialize produced zero bytes for a valid empty-payload entry")
	}

	got := envelope.EntryLeafHash(entry)

	// RFC 6962: h(0x00 || empty-data-but-valid-header-bytes)
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var want [32]byte
	copy(want[:], h.Sum(nil))

	if got != want {
		t.Fatalf("empty-payload EntryLeafHash = %x, want %x", got, want)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 3. MarshalBundleEntry — matches c2sp.org/tlog-tiles framing
// ─────────────────────────────────────────────────────────────────────

// TestMarshalBundleEntry_TLogTilesFraming asserts that the bundle-framed
// bytes are exactly `uint16_BE(len) || data` as specified by
// c2sp.org/tlog-tiles. This is the byte-level contract Tessera's default
// marshalForBundle closure produces; the SDK must match it verbatim for
// the operator to bridge without translation.
func TestMarshalBundleEntry_TLogTilesFraming(t *testing.T) {
	entry := buildTestEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:bundle",
	}, []byte("payload-bytes"))

	data := envelope.Serialize(entry)
	got := envelope.MarshalBundleEntry(entry)

	// Expected shape: 2-byte big-endian length prefix, then data.
	if len(got) != 2+len(data) {
		t.Fatalf("bundle length = %d, want 2 + %d = %d", len(got), len(data), 2+len(data))
	}

	gotLen := binary.BigEndian.Uint16(got[:2])
	if int(gotLen) != len(data) {
		t.Fatalf("bundle length prefix = %d, want %d", gotLen, len(data))
	}

	if !bytes.Equal(got[2:], data) {
		t.Fatal("bundle payload bytes differ from Serialize(entry)")
	}
}

// TestMarshalBundleEntry_RoundTrip asserts that a caller can parse the
// bundle framing back into the original entry bytes. This is the contract
// Tessera EntryBundle readers depend on: read 2 bytes, read len bytes,
// repeat.
func TestMarshalBundleEntry_RoundTrip(t *testing.T) {
	entry := buildTestEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:roundtrip",
	}, []byte("roundtrip-data"))

	framed := envelope.MarshalBundleEntry(entry)
	if len(framed) < 2 {
		t.Fatal("framed bundle too short to contain length prefix")
	}

	declared := binary.BigEndian.Uint16(framed[:2])
	payload := framed[2 : 2+int(declared)]

	// Deserialize the unwrapped bytes and compare against the original.
	decoded, err := envelope.Deserialize(payload)
	if err != nil {
		t.Fatalf("Deserialize on unwrapped bundle payload: %v", err)
	}
	if decoded.Header.SignerDID != entry.Header.SignerDID {
		t.Fatalf("round-trip SignerDID mismatch: got %q, want %q",
			decoded.Header.SignerDID, entry.Header.SignerDID)
	}
	if decoded.Header.Destination != entry.Header.Destination {
		t.Fatalf("round-trip Destination mismatch: got %q, want %q",
			decoded.Header.Destination, entry.Header.Destination)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 4. BundleEntries — concatenated tlog-tiles framing
// ─────────────────────────────────────────────────────────────────────

// TestBundleEntries_ConcatenationMatchesPerEntry asserts that BundleEntries
// produces exactly the concatenation of individual MarshalBundleEntry
// outputs in order. No padding, no trailer, no reordering.
func TestBundleEntries_ConcatenationMatchesPerEntry(t *testing.T) {
	nonNil := types.LogPosition{LogDID: "did:example:log", Sequence: 42}

	e1 := buildTestEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:s1",
	}, []byte("first"))
	e2 := buildTestEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:s2",
		TargetRoot:  &nonNil,
	}, []byte("second"))
	e3 := buildTestEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:s3",
	}, nil)

	bulk := envelope.BundleEntries([]*envelope.Entry{e1, e2, e3})

	var expected []byte
	expected = append(expected, envelope.MarshalBundleEntry(e1)...)
	expected = append(expected, envelope.MarshalBundleEntry(e2)...)
	expected = append(expected, envelope.MarshalBundleEntry(e3)...)

	if !bytes.Equal(bulk, expected) {
		t.Fatalf("BundleEntries (%d bytes) != concatenated MarshalBundleEntry (%d bytes)",
			len(bulk), len(expected))
	}
}

// TestBundleEntries_Empty asserts that bundling zero entries produces
// zero bytes. Unlikely to be called, but the contract should be well-defined.
func TestBundleEntries_Empty(t *testing.T) {
	got := envelope.BundleEntries(nil)
	if len(got) != 0 {
		t.Fatalf("empty bundle length = %d, want 0", len(got))
	}

	got = envelope.BundleEntries([]*envelope.Entry{})
	if len(got) != 0 {
		t.Fatalf("empty bundle length = %d, want 0", len(got))
	}
}

// ─────────────────────────────────────────────────────────────────────
// 5. Cross-primitive consistency
// ─────────────────────────────────────────────────────────────────────

// TestTesseraPrimitives_ShareSameSerializedData asserts that all four
// primitives operate on the same Serialize(entry) bytes. A regression in
// any one of them that caused it to re-serialize with a different field
// order would silently corrupt operator-level consistency.
func TestTesseraPrimitives_ShareSameSerializedData(t *testing.T) {
	entry := buildTestEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:consistency",
	}, []byte("consistency-check"))

	data := envelope.Serialize(entry)

	// Identity = SHA-256(data)
	identityWant := sha256.Sum256(data)
	if envelope.EntryIdentity(entry) != identityWant {
		t.Error("EntryIdentity does not agree with Serialize(entry)")
	}

	// LeafHash = SHA-256(0x00 || data)
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var leafWant [32]byte
	copy(leafWant[:], h.Sum(nil))
	if envelope.EntryLeafHash(entry) != leafWant {
		t.Error("EntryLeafHash does not agree with Serialize(entry)")
	}

	// MarshalBundleEntry = uint16_BE(len) || data
	framed := envelope.MarshalBundleEntry(entry)
	if !bytes.Equal(framed[2:], data) {
		t.Error("MarshalBundleEntry payload does not agree with Serialize(entry)")
	}
}
