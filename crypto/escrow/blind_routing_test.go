// Package escrow — blind_routing_test.go covers the production-only
// types declared in blind_routing.go. The mocks (and their tests)
// live in crypto/escrow/escrowtest under build tag escrow_mocks.
package escrow

import "testing"

// ─────────────────────────────────────────────────────────────────────
// Tiny in-package interface stub
// ─────────────────────────────────────────────────────────────────────
//
// stubEnclave exists ONLY in this _test.go file (and therefore only
// in test binaries for package escrow) to provide a concrete
// EnclaveAttestation implementation against which the interface
// shape can be compile-time asserted. It is intentionally minimal,
// rejects every input, and is never accessible from other packages.

type stubEnclave struct{}

func (stubEnclave) VerifyAttestation([]byte) error { return errAlwaysReject }
func (stubEnclave) Platform() string               { return "stub_test_only" }

var errAlwaysReject = stubError("stubEnclave never accepts")

type stubError string

func (e stubError) Error() string { return string(e) }

// Compile-time assertion: any drift in the EnclaveAttestation
// interface (renamed methods, changed signatures) breaks the build
// here.
var _ EnclaveAttestation = stubEnclave{}

// ─────────────────────────────────────────────────────────────────────
// Stub behavior
// ─────────────────────────────────────────────────────────────────────

func TestStubEnclave_AlwaysRejects(t *testing.T) {
	if err := (stubEnclave{}).VerifyAttestation([]byte{0x01}); err == nil {
		t.Fatal("stub must always reject; got nil error")
	}
}

func TestStubEnclave_PlatformDistinct(t *testing.T) {
	if (stubEnclave{}).Platform() == "" {
		t.Fatal("stub Platform() must be non-empty for log discrimination")
	}
}

// ─────────────────────────────────────────────────────────────────────
// BlindRouteResult
// ─────────────────────────────────────────────────────────────────────

func TestBlindRouteResult_ZeroValue(t *testing.T) {
	var r BlindRouteResult
	if r.CIDs != nil {
		t.Fatalf("zero-value BlindRouteResult.CIDs = %v, want nil", r.CIDs)
	}
}

func TestBlindRouteResult_HoldsCIDs(t *testing.T) {
	r := BlindRouteResult{CIDs: []string{"bafy...a", "bafy...b"}}
	if len(r.CIDs) != 2 {
		t.Fatalf("len(CIDs) = %d, want 2", len(r.CIDs))
	}
	if r.CIDs[0] != "bafy...a" || r.CIDs[1] != "bafy...b" {
		t.Fatal("CIDs content mismatch")
	}
}

// ─────────────────────────────────────────────────────────────────────
// BlindRouteShares — function-type usability
// ─────────────────────────────────────────────────────────────────────

func TestBlindRouteShares_NilTypeUsable(t *testing.T) {
	var fn BlindRouteShares
	if fn != nil {
		t.Fatal("nil function literal compared non-nil")
	}
}

func TestBlindRouteShares_Callable(t *testing.T) {
	// A non-nil BlindRouteShares must be callable with the
	// declared signature. This catches signature drift (e.g.,
	// someone changing [][]byte to []byte).
	called := false
	var fn BlindRouteShares = func(blobs [][]byte) (*BlindRouteResult, error) {
		called = true
		out := make([]string, len(blobs))
		for i := range blobs {
			out[i] = "cid"
		}
		return &BlindRouteResult{CIDs: out}, nil
	}
	res, err := fn([][]byte{{0x01}, {0x02}})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !called {
		t.Fatal("function not invoked")
	}
	if len(res.CIDs) != 2 {
		t.Fatalf("expected 2 CIDs, got %d", len(res.CIDs))
	}
}
