// Package escrow — verify_share_test.go tests ValidateShareFormat (per-share
// structural validity) and VerifyShareSet (mutual consistency and threshold).
package escrow

import (
	"errors"
	"testing"
)

// -------------------------------------------------------------------------------------------------
// ValidateShareFormat — success path
// -------------------------------------------------------------------------------------------------

func TestValidateShareFormat_ValidV1(t *testing.T) {
	s := validV1Share(1, 3)
	if err := ValidateShareFormat(s); err != nil {
		t.Fatalf("ValidateShareFormat on valid V1 share: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// ValidateShareFormat — six failure modes enumerated in the doc
// -------------------------------------------------------------------------------------------------

func TestValidateShareFormat_RejectsUnsupportedVersion(t *testing.T) {
	s := validV1Share(1, 3)
	s.Version = 0xFF
	err := ValidateShareFormat(s)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("got %v, want ErrUnsupportedVersion", err)
	}
}

// TestValidateShareFormat_RejectsMalformedV2 asserts that a share
// carrying the V2 Version byte but V1-shaped contents (zero
// BlindingFactor, zero CommitmentHash) is hard-rejected.
//
// V2 is now shipped and accepted when well-formed — this test locks
// the V2 branch's empty-field gate. Pre-Phase-B this test was
// "RejectsV2" and asserted ErrUnsupportedVersion.
func TestValidateShareFormat_RejectsMalformedV2(t *testing.T) {
	s := validV1Share(1, 3)
	s.Version = VersionV2
	// BlindingFactor and CommitmentHash are still [32]byte{} from
	// validV1Share; this is exactly the malformed V2 shape.
	err := ValidateShareFormat(s)
	if !errors.Is(err, ErrV2FieldEmpty) {
		t.Fatalf("got %v, want ErrV2FieldEmpty for malformed V2", err)
	}
}

// TestValidateShareFormat_AcceptsWellFormedV2 locks the positive
// V2 path: a share with populated BlindingFactor, CommitmentHash,
// and SchemePedersenTag is accepted.
func TestValidateShareFormat_AcceptsWellFormedV2(t *testing.T) {
	s := validV1Share(1, 3)
	s.Version = VersionV2
	s.FieldTag = SchemePedersenTag
	for i := range s.BlindingFactor {
		s.BlindingFactor[i] = byte(i) + 1
	}
	for i := range s.CommitmentHash {
		s.CommitmentHash[i] = byte(i) ^ 0xAA
	}
	if err := ValidateShareFormat(s); err != nil {
		t.Fatalf("well-formed V2 share rejected: %v", err)
	}
}

func TestValidateShareFormat_RejectsThresholdZero(t *testing.T) {
	s := validV1Share(1, 0)
	err := ValidateShareFormat(s)
	if !errors.Is(err, ErrInvalidThreshold) {
		t.Fatalf("got %v, want ErrInvalidThreshold", err)
	}
}

func TestValidateShareFormat_RejectsThresholdOne(t *testing.T) {
	// Threshold=1 is degenerate — single share would trivially
	// reconstruct the secret.
	s := validV1Share(1, 1)
	err := ValidateShareFormat(s)
	if !errors.Is(err, ErrInvalidThreshold) {
		t.Fatalf("got %v, want ErrInvalidThreshold for threshold=1", err)
	}
}

func TestValidateShareFormat_RejectsIndexZero(t *testing.T) {
	// Index 0 is reserved: evaluating f(0) would reveal the secret.
	s := validV1Share(0, 3)
	err := ValidateShareFormat(s)
	if !errors.Is(err, ErrInvalidIndex) {
		t.Fatalf("got %v, want ErrInvalidIndex for index=0", err)
	}
}

func TestValidateShareFormat_RejectsZeroSplitID(t *testing.T) {
	s := validV1Share(1, 3)
	s.SplitID = [32]byte{}
	err := ValidateShareFormat(s)
	if !errors.Is(err, ErrSplitIDMissing) {
		t.Fatalf("got %v, want ErrSplitIDMissing", err)
	}
}

func TestValidateShareFormat_RejectsNonZeroBlindingFactor(t *testing.T) {
	// V1 must not populate V2-only fields.
	s := validV1Share(1, 3)
	s.BlindingFactor[0] = 0x01
	err := ValidateShareFormat(s)
	if !errors.Is(err, ErrV1FieldNotEmpty) {
		t.Fatalf("got %v, want ErrV1FieldNotEmpty (BlindingFactor)", err)
	}
}

func TestValidateShareFormat_RejectsNonZeroCommitmentHash(t *testing.T) {
	s := validV1Share(1, 3)
	s.CommitmentHash[31] = 0x01
	err := ValidateShareFormat(s)
	if !errors.Is(err, ErrV1FieldNotEmpty) {
		t.Fatalf("got %v, want ErrV1FieldNotEmpty (CommitmentHash)", err)
	}
}

// -------------------------------------------------------------------------------------------------
// VerifyShareSet — happy path
// -------------------------------------------------------------------------------------------------

func TestVerifyShareSet_ValidSetMeetsThreshold(t *testing.T) {
	secret := newTestSecret(t, 0x10)
	shares, _ := splitTestSecret(t, secret, 3, 5)
	// Use exactly threshold.
	if err := VerifyShareSet(shares[:3]); err != nil {
		t.Fatalf("VerifyShareSet with 3 valid shares (M=3): %v", err)
	}
}

func TestVerifyShareSet_ValidSetAboveThreshold(t *testing.T) {
	secret := newTestSecret(t, 0x20)
	shares, _ := splitTestSecret(t, secret, 3, 5)
	// Use all 5 shares — still valid.
	if err := VerifyShareSet(shares); err != nil {
		t.Fatalf("VerifyShareSet with 5 valid shares (M=3): %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// VerifyShareSet — rejection modes
// -------------------------------------------------------------------------------------------------

func TestVerifyShareSet_RejectsEmpty(t *testing.T) {
	err := VerifyShareSet(nil)
	if !errors.Is(err, ErrEmptyShareSet) {
		t.Fatalf("got %v, want ErrEmptyShareSet", err)
	}
}

func TestVerifyShareSet_RejectsBelowThreshold(t *testing.T) {
	secret := newTestSecret(t, 0x30)
	shares, _ := splitTestSecret(t, secret, 3, 5)
	err := VerifyShareSet(shares[:2]) // below M=3
	if !errors.Is(err, ErrBelowThreshold) {
		t.Fatalf("got %v, want ErrBelowThreshold", err)
	}
}

func TestVerifyShareSet_RejectsVersionMismatch(t *testing.T) {
	secret := newTestSecret(t, 0x40)
	shares, _ := splitTestSecret(t, secret, 3, 5)
	// Tamper share[1]'s version. Since ValidateShareFormat runs first
	// per-share, an unsupported version triggers that error before
	// cross-share consistency checks. Tests the per-share validation
	// path rather than the set-level mismatch — which is what we want
	// because we don't have two valid Version values that both pass
	// ValidateShareFormat (V2 is rejected).
	shares[1].Version = 0xFF
	err := VerifyShareSet(shares[:3])
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("got %v, want ErrUnsupportedVersion", err)
	}
}

func TestVerifyShareSet_RejectsThresholdMismatch(t *testing.T) {
	// Build two share-sets with the same SplitID but different
	// Threshold values, then mix them. This is a crafted scenario
	// (can't naturally produce this via Split alone); we do it
	// manually to exercise the set-level check.
	s1 := validV1Share(1, 3)
	s2 := validV1Share(2, 5) // different threshold
	s2.SplitID = s1.SplitID  // same SplitID to reach the Threshold check
	err := VerifyShareSet([]Share{s1, s2})
	if !errors.Is(err, ErrThresholdMismatch) {
		t.Fatalf("got %v, want ErrThresholdMismatch", err)
	}
}

func TestVerifyShareSet_RejectsSplitIDMismatch(t *testing.T) {
	secret1 := newTestSecret(t, 0x50)
	secret2 := newTestSecret(t, 0x60)
	sharesA, _ := splitTestSecret(t, secret1, 3, 5)
	sharesB, _ := splitTestSecret(t, secret2, 3, 5)
	// Mix one share from each split (different SplitID by construction —
	// Split generates a random per-call ID).
	mixed := []Share{sharesA[0], sharesA[1], sharesB[2]}
	err := VerifyShareSet(mixed)
	if !errors.Is(err, ErrSplitIDMismatch) {
		t.Fatalf("got %v, want ErrSplitIDMismatch", err)
	}
}

func TestVerifyShareSet_RejectsDuplicateIndex(t *testing.T) {
	secret := newTestSecret(t, 0x70)
	shares, _ := splitTestSecret(t, secret, 3, 5)
	// Force a duplicate index.
	shares[1].Index = shares[0].Index
	err := VerifyShareSet(shares[:3])
	if !errors.Is(err, ErrDuplicateIndex) {
		t.Fatalf("got %v, want ErrDuplicateIndex", err)
	}
}
