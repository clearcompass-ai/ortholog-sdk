// Package escrow — verify_share_binding_test.go holds the binding
// tests for the five mutation-audit switches in
// verify_share_mutation_switches.go. See
// crypto/escrow/verify_share.mutation-audit.yaml for the registry.
//
// Each test is tight: constructs a share shape that ONLY the target
// gate can reject, asserts the specific sentinel error fires, and
// would silently pass if the gate were disabled (the downstream
// checks would not catch the same malformation).
package escrow

import (
	"errors"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────

// nonZeroArr32 returns a 32-byte array with a non-zero pattern.
func nonZeroArr32(seed byte) [32]byte {
	var a [32]byte
	for i := range a {
		a[i] = seed + byte(i)
	}
	return a
}

// validV2ShareForBinding constructs a V2 share that passes
// ValidateShareFormat. Used as the starting point for tests that
// mutate exactly one field to exercise a specific gate.
func validV2ShareForBinding() Share {
	return Share{
		Version:        VersionV2,
		Threshold:      3,
		Index:          1,
		Value:          nonZeroArr32(0x11),
		BlindingFactor: nonZeroArr32(0x22),
		CommitmentHash: nonZeroArr32(0x33),
		SplitID:        nonZeroArr32(0x44),
		FieldTag:       SchemePedersenTag,
	}
}

// validV1ShareForBinding constructs a V1 share that passes
// ValidateShareFormat. Mirrors validV1Share but local to this file
// to keep the binding test self-contained.
func validV1ShareForBinding() Share {
	return Share{
		Version:   VersionV1,
		Threshold: 3,
		Index:     1,
		Value:     nonZeroArr32(0x55),
		SplitID:   nonZeroArr32(0x66),
		FieldTag:  SchemeGF256Tag,
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableV1FieldEmptyCheck
// ─────────────────────────────────────────────────────────────────────

// TestValidateShareFormatV1_V1FieldEmpty_Binding pins that a V1
// share with a non-zero BlindingFactor is rejected with
// ErrV1FieldNotEmpty. Flipping the switch off lets the V2-field-
// forgery path through — a V1 share that pretends to be Pedersen-
// bound without the commitment-hash contract.
func TestValidateShareFormatV1_V1FieldEmpty_Binding(t *testing.T) {
	s := validV1ShareForBinding()
	s.BlindingFactor = nonZeroArr32(0xDD)
	err := ValidateShareFormat(s)
	if !errors.Is(err, ErrV1FieldNotEmpty) {
		t.Fatalf("want ErrV1FieldNotEmpty, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableV2FieldPopulatedCheck
// ─────────────────────────────────────────────────────────────────────

// TestValidateShareFormatV2_V2FieldPopulated_Binding pins that a
// V2 share with a zero BlindingFactor is rejected with
// ErrV2FieldEmpty. Flipping the switch off admits an ill-formed V2
// share that would confuse downstream Pedersen verification.
func TestValidateShareFormatV2_V2FieldPopulated_Binding(t *testing.T) {
	s := validV2ShareForBinding()
	s.BlindingFactor = [32]byte{} // zero
	err := ValidateShareFormat(s)
	if !errors.Is(err, ErrV2FieldEmpty) {
		t.Fatalf("want ErrV2FieldEmpty, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableShareIndexNonZero
// ─────────────────────────────────────────────────────────────────────

// TestValidateShareFormat_IndexNonZero_Binding pins that a share
// with Index = 0 is rejected with ErrInvalidIndex. Exercised on
// both V1 and V2 via the common path.
func TestValidateShareFormat_IndexNonZero_Binding(t *testing.T) {
	for _, make := range []func() Share{
		validV1ShareForBinding,
		validV2ShareForBinding,
	} {
		s := make()
		s.Index = 0
		err := ValidateShareFormat(s)
		if !errors.Is(err, ErrInvalidIndex) {
			t.Fatalf("version 0x%02x: want ErrInvalidIndex, got %v", s.Version, err)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableSplitIDPresent
// ─────────────────────────────────────────────────────────────────────

// TestValidateShareFormat_SplitIDPresent_Binding pins that a share
// with SplitID = 0 is rejected with ErrSplitIDMissing. Exercised
// on both V1 and V2.
func TestValidateShareFormat_SplitIDPresent_Binding(t *testing.T) {
	for _, make := range []func() Share{
		validV1ShareForBinding,
		validV2ShareForBinding,
	} {
		s := make()
		s.SplitID = [32]byte{}
		err := ValidateShareFormat(s)
		if !errors.Is(err, ErrSplitIDMissing) {
			t.Fatalf("version 0x%02x: want ErrSplitIDMissing, got %v", s.Version, err)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableFieldTagDiscrimination
// ─────────────────────────────────────────────────────────────────────

// TestValidateShareFormat_FieldTagDiscrimination_Binding pins that
// a share carrying an unknown non-zero FieldTag is rejected with
// ErrUnknownFieldTag. Exercised on both V1 (tag must be 0 or GF256)
// and V2 (tag must be 0 or Pedersen).
func TestValidateShareFormat_FieldTagDiscrimination_Binding(t *testing.T) {
	// V1 path: swap in the Pedersen tag (wrong scheme for V1).
	v1 := validV1ShareForBinding()
	v1.FieldTag = SchemePedersenTag
	err := ValidateShareFormat(v1)
	if !errors.Is(err, ErrUnknownFieldTag) {
		t.Fatalf("V1 with Pedersen tag: want ErrUnknownFieldTag, got %v", err)
	}

	// V2 path: swap in the GF256 tag (wrong scheme for V2).
	v2 := validV2ShareForBinding()
	v2.FieldTag = SchemeGF256Tag
	err = ValidateShareFormat(v2)
	if !errors.Is(err, ErrUnknownFieldTag) {
		t.Fatalf("V2 with GF256 tag: want ErrUnknownFieldTag, got %v", err)
	}

	// Either-version path: an unrecognised tag value.
	other := validV2ShareForBinding()
	other.FieldTag = 0xEE
	err = ValidateShareFormat(other)
	if !errors.Is(err, ErrUnknownFieldTag) {
		t.Fatalf("V2 with tag 0xEE: want ErrUnknownFieldTag, got %v", err)
	}
}
