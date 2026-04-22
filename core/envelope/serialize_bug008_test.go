/*
FILE PATH:

	core/envelope/serialize_bug008_test.go

DESCRIPTION:

	Tests for BUG-008 fix: validateHeaderForWrite must reject oversize
	SignerDIDs at write time using the pre-existing MaxSignerDIDLen
	constant, rather than silently admitting them and letting
	appendLenPrefixedString truncate at 65535 bytes during encoding.

	Before the fix: a caller passing a multi-KB misconfigured string
	as SignerDID would get a successfully-serialized entry whose
	on-wire identity was truncated. The Signatures[0] invariant
	check would pass because it compared truncated-against-truncated,
	and the log would attest to an identifier the caller never sent.

	Tests added in this patch:

	  TestValidateHeaderForWrite_RejectsOversizeSignerDID
	    BUG-008 headline regression guard. A SignerDID one byte over
	    MaxSignerDIDLen must be rejected with ErrHeaderSignerDIDTooLong.

	  TestValidateHeaderForWrite_AcceptsAtMaxSignerDIDLen
	    Boundary test. Exactly MaxSignerDIDLen bytes is accepted.

	  TestValidateHeaderForWrite_AcceptsTypicalSignerDID
	    Positive control with a realistic DID (~30 bytes).

	  TestNewUnsignedEntry_RejectsOversizeSignerDID
	    End-to-end check through the constructor surface callers
	    actually use. NewUnsignedEntry invokes validateHeaderForWrite;
	    the error must propagate.

MUTATION PROBE
──────────────
In validateHeaderForWrite, comment out the BUG-008 fix block:

	// if len(h.SignerDID) > MaxSignerDIDLen {
	//     return fmt.Errorf("%w: length %d exceeds cap %d",
	//         ErrHeaderSignerDIDTooLong, len(h.SignerDID), MaxSignerDIDLen)
	// }

Run: go test -count=1 -v -run TestValidateHeaderForWrite_RejectsOversizeSignerDID ./core/envelope/
Expected: FAIL with "BUG-008 REGRESSION: validateHeaderForWrite accepted..."

Restore the block. Re-run. All four tests pass.
*/
package envelope

import (
	"errors"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════
// Test helpers
// ═══════════════════════════════════════════════════════════════════

// validHeaderWithSignerDID returns a ControlHeader with the given
// SignerDID and otherwise-valid fields. Useful when only SignerDID
// length matters to the test.
func validHeaderWithSignerDID(signerDID string) ControlHeader {
	return ControlHeader{
		SignerDID:   signerDID,
		Destination: "did:web:target-exchange",
		EventTime:   1_700_000_000_000_000, // micros, arbitrary
	}
}

// ═══════════════════════════════════════════════════════════════════
// BUG-008 headline test
// ═══════════════════════════════════════════════════════════════════

// TestValidateHeaderForWrite_RejectsOversizeSignerDID is the BUG-008
// regression guard. A SignerDID one byte over MaxSignerDIDLen must be
// rejected with ErrHeaderSignerDIDTooLong.
//
// Before the fix: validateHeaderForWrite accepted the header, the
// entry serialized with a truncated SignerDID, and the caller's
// identifier was silently corrupted. After the fix: rejected at
// validation before any bytes are written.
func TestValidateHeaderForWrite_RejectsOversizeSignerDID(t *testing.T) {
	// One byte over the cap.
	oversized := strings.Repeat("a", MaxSignerDIDLen+1)
	header := validHeaderWithSignerDID(oversized)

	err := validateHeaderForWrite(&header)

	if err == nil {
		t.Fatalf("BUG-008 REGRESSION: validateHeaderForWrite accepted "+
			"SignerDID of length %d (cap is %d). The length cap is "+
			"missing or broken; oversize DIDs will be silently "+
			"truncated at encode time, corrupting entry identity.",
			len(oversized), MaxSignerDIDLen)
	}
	if !errors.Is(err, ErrHeaderSignerDIDTooLong) {
		t.Fatalf("expected ErrHeaderSignerDIDTooLong, got: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════
// Boundary + positive controls
// ═══════════════════════════════════════════════════════════════════

// TestValidateHeaderForWrite_AcceptsAtMaxSignerDIDLen confirms that a
// SignerDID of exactly MaxSignerDIDLen bytes is accepted. The cap is
// inclusive — rejection begins at MaxSignerDIDLen+1.
//
// This guards against an off-by-one that would reject legitimate
// max-length DIDs.
func TestValidateHeaderForWrite_AcceptsAtMaxSignerDIDLen(t *testing.T) {
	// Exactly at the cap.
	atCap := strings.Repeat("a", MaxSignerDIDLen)
	header := validHeaderWithSignerDID(atCap)

	err := validateHeaderForWrite(&header)

	if err != nil {
		t.Fatalf("boundary: SignerDID of exactly MaxSignerDIDLen (%d) "+
			"was rejected: %v. The cap is off by one.",
			MaxSignerDIDLen, err)
	}
}

// TestValidateHeaderForWrite_AcceptsTypicalSignerDID is the positive
// control. A realistic DID (well under the cap) is accepted.
//
// If this test fails after the BUG-008 fix, the cap is over-restrictive.
func TestValidateHeaderForWrite_AcceptsTypicalSignerDID(t *testing.T) {
	header := validHeaderWithSignerDID("did:web:ortholog.example.com:issuer:1")

	err := validateHeaderForWrite(&header)

	if err != nil {
		t.Fatalf("positive control failed: typical DID rejected: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════
// End-to-end via constructor
// ═══════════════════════════════════════════════════════════════════

// TestNewUnsignedEntry_RejectsOversizeSignerDID confirms the fix
// propagates through NewUnsignedEntry, the constructor all 18 builders
// in builder/entry_builders.go use. Ensures the guard covers the
// actual caller surface, not just the internal validation function.
func TestNewUnsignedEntry_RejectsOversizeSignerDID(t *testing.T) {
	oversized := strings.Repeat("a", MaxSignerDIDLen+1)
	header := validHeaderWithSignerDID(oversized)

	entry, err := NewUnsignedEntry(header, []byte("test-payload"))

	if err == nil {
		t.Fatalf("NewUnsignedEntry returned a non-nil entry (%v) for "+
			"an oversize SignerDID. The BUG-008 fix does not propagate "+
			"through this constructor.", entry)
	}
	if !errors.Is(err, ErrHeaderSignerDIDTooLong) {
		t.Fatalf("expected ErrHeaderSignerDIDTooLong, got: %v", err)
	}
	if entry != nil {
		t.Fatal("NewUnsignedEntry returned a non-nil entry despite error")
	}
}
