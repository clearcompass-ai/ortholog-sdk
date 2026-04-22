package artifact

import (
	"errors"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────
// ZeroKey
// ─────────────────────────────────────────────────────────────────

// TestZeroKey_NilSafe locks in the nil-receiver no-op contract.
// Mirrors crypto/escrow.ZeroArray32's nil-safety so every zeroizer
// in the SDK behaves the same way for unguarded defer chains.
func TestZeroKey_NilSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ZeroKey(nil) panicked: %v", r)
		}
	}()
	ZeroKey(nil)
}

// TestZeroKey_ZeroesBoth confirms both Key and Nonce land at zero
// after the call, regardless of their starting bytes.
func TestZeroKey_ZeroesBoth(t *testing.T) {
	key := &ArtifactKey{}
	for i := range key.Key {
		key.Key[i] = 0xAA
	}
	for i := range key.Nonce {
		key.Nonce[i] = 0xBB
	}
	ZeroKey(key)
	for i, b := range key.Key {
		if b != 0 {
			t.Fatalf("Key[%d] = 0x%02x, want 0", i, b)
		}
	}
	for i, b := range key.Nonce {
		if b != 0 {
			t.Fatalf("Nonce[%d] = 0x%02x, want 0", i, b)
		}
	}
}

// ─────────────────────────────────────────────────────────────────
// IrrecoverableError
// ─────────────────────────────────────────────────────────────────

// TestNewIrrecoverableError_NilCauseSubstitutesSentinel confirms
// the constructor's nil-Cause defense: ErrIrrecoverableNilCause
// surfaces through both Error() and errors.Is.
func TestNewIrrecoverableError_NilCauseSubstitutesSentinel(t *testing.T) {
	e := NewIrrecoverableError(nil)
	if e == nil {
		t.Fatal("NewIrrecoverableError(nil) returned a nil pointer")
	}
	if !strings.Contains(e.Error(), ErrIrrecoverableNilCause.Error()) {
		t.Fatalf("Error() = %q, want containing %q", e.Error(), ErrIrrecoverableNilCause.Error())
	}
	if !errors.Is(e, ErrIrrecoverableNilCause) {
		t.Fatal("errors.Is(NewIrrecoverableError(nil), ErrIrrecoverableNilCause) = false, want true")
	}
}

// TestIrrecoverableError_DirectLiteralNilCause_UnwrapsSentinel
// locks the symmetric behaviour: even when someone bypasses the
// constructor and builds the literal &IrrecoverableError{Cause: nil}
// directly, ErrIrrecoverableNilCause still surfaces through
// errors.Is. This is the load-bearing audit-friendly property —
// detection MUST NOT depend on which construction path produced
// the error.
func TestIrrecoverableError_DirectLiteralNilCause_UnwrapsSentinel(t *testing.T) {
	e := &IrrecoverableError{Cause: nil}
	if !errors.Is(e, ErrIrrecoverableNilCause) {
		t.Fatal("errors.Is(&IrrecoverableError{Cause: nil}, ErrIrrecoverableNilCause) = false, " +
			"want true — symmetry with NewIrrecoverableError(nil) is broken")
	}
	if !strings.Contains(e.Error(), ErrIrrecoverableNilCause.Error()) {
		t.Fatalf("direct-literal Error() = %q, want containing %q",
			e.Error(), ErrIrrecoverableNilCause.Error())
	}
}

// TestIrrecoverableError_NilStructSafe asserts methods do not
// panic on a typed-nil receiver — the contract for any error type
// callers might funnel through generic wrappers.
func TestIrrecoverableError_NilStructSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("(*IrrecoverableError)(nil) method call panicked: %v", r)
		}
	}()
	var e *IrrecoverableError
	_ = e.Error()
	if got := e.Unwrap(); got != nil {
		t.Fatalf("nil-receiver Unwrap() = %v, want nil (no underlying cause to surface)", got)
	}
}

// TestIsIrrecoverable_StillMatches proves the constructor change
// does not break the IsIrrecoverable detection contract.
func TestIsIrrecoverable_StillMatches(t *testing.T) {
	real := errors.New("genuine cause")
	wrapped := NewIrrecoverableError(real)
	if !IsIrrecoverable(wrapped) {
		t.Fatal("IsIrrecoverable(NewIrrecoverableError(real)) = false, want true")
	}
	if !errors.Is(wrapped, real) {
		t.Fatal("errors.Is should reach the wrapped cause through Unwrap")
	}
}

// TestIsIrrecoverable_NotMatching confirms the negative side: an
// error that is not an IrrecoverableError returns false.
func TestIsIrrecoverable_NotMatching(t *testing.T) {
	if IsIrrecoverable(errors.New("plain error")) {
		t.Fatal("IsIrrecoverable(plain) = true, want false")
	}
	if IsIrrecoverable(nil) {
		t.Fatal("IsIrrecoverable(nil) = true, want false")
	}
}
