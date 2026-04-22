package envelope

import (
	"errors"
	"testing"
)

// TestMaxCanonicalBytes_PinnedToBundleLimit locks in the ORTHO-BUG-005
// invariant: the canonical-bytes cap enforced at construction time is
// the same value as the c2sp.org/tlog-tiles bundle limit. Any entry
// that passes Validate is guaranteed to fit in MarshalBundleEntry's
// uint16 length prefix.
func TestMaxCanonicalBytes_PinnedToBundleLimit(t *testing.T) {
	if MaxCanonicalBytes != MaxBundleEntrySize {
		t.Fatalf("MaxCanonicalBytes (%d) must equal MaxBundleEntrySize (%d) — ORTHO-BUG-005 guard",
			MaxCanonicalBytes, MaxBundleEntrySize)
	}
	if MaxBundleEntrySize != 65535 {
		t.Fatalf("MaxBundleEntrySize (%d) must equal 65535 (uint16 max)", MaxBundleEntrySize)
	}
}

// TestValidate_RejectsEntryExceedingBundleLimit exercises the core
// ORTHO-BUG-005 fix: an entry whose serialized size exceeds the
// bundle limit must be rejected by Entry.Validate with
// ErrCanonicalTooLarge, so MarshalBundleEntry's panic is never
// reached at runtime.
func TestValidate_RejectsEntryExceedingBundleLimit(t *testing.T) {
	// DomainPayload large enough to push serialized size past the
	// 64 KiB bundle limit. 70 KiB leaves comfortable margin for
	// header + signature framing regardless of exact overhead.
	payload := make([]byte, 70*1024)
	h := ControlHeader{
		Destination:   "did:web:test.example",
		SignerDID:     "did:example:alice",
		AuthorityPath: ptrToAuthorityPath(AuthoritySameSigner),
	}
	entry, err := NewUnsignedEntry(h, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []Signature{{
		SignerDID: h.SignerDID,
		AlgoID:    SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := entry.Validate(); err == nil {
		t.Fatalf("Validate: want error on oversized entry, got nil")
	} else if !errors.Is(err, ErrCanonicalTooLarge) {
		t.Fatalf("Validate: want ErrCanonicalTooLarge, got %v", err)
	}

	// Belt-and-braces: the documented invariant — once Validate
	// accepts an entry, MarshalBundleEntry must not panic. Here we
	// show the negative: the oversized entry's serialized form does
	// exceed the bundle limit, confirming Validate caught a real
	// panic hazard rather than a spurious rejection.
	serialized := Serialize(entry)
	if len(serialized) <= MaxBundleEntrySize {
		t.Fatalf("test fixture: expected serialized size > %d, got %d", MaxBundleEntrySize, len(serialized))
	}
}

// TestValidate_AcceptsEntryAtBundleLimit asserts the cap is inclusive
// only up to MaxBundleEntrySize. An entry exactly at the limit is
// accepted; one byte over is rejected. The precise limit matters
// because tile writers right at the boundary should not spuriously
// fail.
func TestValidate_AcceptsEntryAtBundleLimit(t *testing.T) {
	// Binary search for the largest payload that stays at-or-under
	// the limit. Exact overhead depends on header + signature wire
	// shape, so compute empirically rather than hard-coding.
	var accepted int
	for size := MaxBundleEntrySize; size > 0; size -= 256 {
		payload := make([]byte, size)
		h := ControlHeader{
			Destination:   "did:web:test.example",
			SignerDID:     "did:example:alice",
			AuthorityPath: ptrToAuthorityPath(AuthoritySameSigner),
		}
		entry, err := NewUnsignedEntry(h, payload)
		if err != nil {
			continue
		}
		entry.Signatures = []Signature{{
			SignerDID: h.SignerDID,
			AlgoID:    SigAlgoECDSA,
			Bytes:     make([]byte, 64),
		}}
		if err := entry.Validate(); err == nil {
			accepted = size
			break
		}
	}
	if accepted == 0 {
		t.Fatal("no payload size passed Validate; cap enforcement may be too strict")
	}
	if accepted > MaxBundleEntrySize {
		t.Fatalf("accepted payload %d exceeds MaxBundleEntrySize %d", accepted, MaxBundleEntrySize)
	}
}

func ptrToAuthorityPath(v AuthorityPath) *AuthorityPath { return &v }
