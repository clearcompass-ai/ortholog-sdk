package escrow

import (
	"errors"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────
// Happy path — baseline for the per-gate mutation tests below
// ─────────────────────────────────────────────────────────────────────

func TestEscrowSplitCommitment_VerifyHappyPath(t *testing.T) {
	_, nonce, _ := canonicalEscrowFixture(t)
	c := buildSyntheticEscrowCommitment(t, 3, 5)
	if err := VerifyEscrowSplitCommitment(&c, nonce); err != nil {
		t.Fatalf("Verify happy path: %v", err)
	}
}

func TestEscrowSplitCommitment_VerifyNil(t *testing.T) {
	_, nonce, _ := canonicalEscrowFixture(t)
	if err := VerifyEscrowSplitCommitment(nil, nonce); !errors.Is(err, ErrEscrowCommitmentSetLength) {
		t.Fatalf("want ErrEscrowCommitmentSetLength on nil, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableEscrowCommitmentOnCurveGate
// ─────────────────────────────────────────────────────────────────────

// TestEscrowSplitCommitment_VerifyRejectsOffCurvePoint pins that an
// off-curve point in CommitmentSet is rejected. Binds
// muEnableEscrowCommitmentOnCurveGate: flipping it false would allow
// the off-curve point to pass the on-curve gate.
func TestEscrowSplitCommitment_VerifyRejectsOffCurvePoint(t *testing.T) {
	_, nonce, _ := canonicalEscrowFixture(t)
	c := buildSyntheticEscrowCommitment(t, 3, 5)
	// 0x02 || 0x00...00 — (0, y) with y²=7 has no root in F_p.
	for i := range c.CommitmentSet[1] {
		c.CommitmentSet[1][i] = 0
	}
	c.CommitmentSet[1][0] = 0x02
	if err := VerifyEscrowSplitCommitment(&c, nonce); !errors.Is(err, ErrEscrowCommitmentPointOffCurve) {
		t.Fatalf("want ErrEscrowCommitmentPointOffCurve, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableEscrowCommitmentSetLengthCheck
// ─────────────────────────────────────────────────────────────────────

func TestEscrowSplitCommitment_VerifyRejectsShortCommitmentSet(t *testing.T) {
	_, nonce, _ := canonicalEscrowFixture(t)
	c := buildSyntheticEscrowCommitment(t, 3, 5)
	c.CommitmentSet = c.CommitmentSet[:2]
	if err := VerifyEscrowSplitCommitment(&c, nonce); !errors.Is(err, ErrEscrowCommitmentSetLength) {
		t.Fatalf("want ErrEscrowCommitmentSetLength, got %v", err)
	}
}

func TestEscrowSplitCommitment_VerifyRejectsLongCommitmentSet(t *testing.T) {
	_, nonce, _ := canonicalEscrowFixture(t)
	c := buildSyntheticEscrowCommitment(t, 3, 5)
	c.CommitmentSet = append(c.CommitmentSet, syntheticEscrowCompressedPoint(t, 4))
	if err := VerifyEscrowSplitCommitment(&c, nonce); !errors.Is(err, ErrEscrowCommitmentSetLength) {
		t.Fatalf("want ErrEscrowCommitmentSetLength, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableEscrowThresholdBoundsCheck
// ─────────────────────────────────────────────────────────────────────

func TestEscrowSplitCommitment_VerifyRejectsThresholdBelowMin(t *testing.T) {
	_, nonce, _ := canonicalEscrowFixture(t)
	c := buildSyntheticEscrowCommitment(t, 2, 5)
	c.M = 1
	if err := VerifyEscrowSplitCommitment(&c, nonce); !errors.Is(err, ErrEscrowCommitmentThresholdBounds) {
		t.Fatalf("M=1: want ErrEscrowCommitmentThresholdBounds, got %v", err)
	}
	c.M = 0
	if err := VerifyEscrowSplitCommitment(&c, nonce); !errors.Is(err, ErrEscrowCommitmentThresholdBounds) {
		t.Fatalf("M=0: want ErrEscrowCommitmentThresholdBounds, got %v", err)
	}
}

func TestEscrowSplitCommitment_VerifyRejectsMAboveN(t *testing.T) {
	_, nonce, _ := canonicalEscrowFixture(t)
	c := buildSyntheticEscrowCommitment(t, 5, 7)
	c.M = 5
	c.N = 3
	if err := VerifyEscrowSplitCommitment(&c, nonce); !errors.Is(err, ErrEscrowCommitmentThresholdBounds) {
		t.Fatalf("want ErrEscrowCommitmentThresholdBounds, got %v", err)
	}
}

func TestEscrowSplitCommitment_VerifyRejectsNZero(t *testing.T) {
	_, nonce, _ := canonicalEscrowFixture(t)
	c := buildSyntheticEscrowCommitment(t, 2, 2)
	c.N = 0
	if err := VerifyEscrowSplitCommitment(&c, nonce); !errors.Is(err, ErrEscrowCommitmentThresholdBounds) {
		t.Fatalf("want ErrEscrowCommitmentThresholdBounds, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableEscrowSplitIDRecomputation
// ─────────────────────────────────────────────────────────────────────

func TestEscrowSplitCommitment_VerifyRejectsWrongSplitID(t *testing.T) {
	_, nonce, _ := canonicalEscrowFixture(t)
	c := buildSyntheticEscrowCommitment(t, 3, 5)
	c.SplitID[0] ^= 0x01
	if err := VerifyEscrowSplitCommitment(&c, nonce); !errors.Is(err, ErrEscrowCommitmentSplitIDMismatch) {
		t.Fatalf("want ErrEscrowCommitmentSplitIDMismatch, got %v", err)
	}
}

func TestEscrowSplitCommitment_VerifyRejectsWrongDealerDID(t *testing.T) {
	_, nonce, _ := canonicalEscrowFixture(t)
	c := buildSyntheticEscrowCommitment(t, 3, 5)
	c.DealerDID = "did:web:attacker.example.com"
	if err := VerifyEscrowSplitCommitment(&c, nonce); !errors.Is(err, ErrEscrowCommitmentSplitIDMismatch) {
		t.Fatalf("want ErrEscrowCommitmentSplitIDMismatch, got %v", err)
	}
}

func TestEscrowSplitCommitment_VerifyRejectsWrongNonce(t *testing.T) {
	_, _, _ = canonicalEscrowFixture(t)
	c := buildSyntheticEscrowCommitment(t, 3, 5)
	var wrongNonce [32]byte
	wrongNonce[0] = 0xFF
	if err := VerifyEscrowSplitCommitment(&c, wrongNonce); !errors.Is(err, ErrEscrowCommitmentSplitIDMismatch) {
		t.Fatalf("want ErrEscrowCommitmentSplitIDMismatch, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Defense-in-depth: gate ordering
// ─────────────────────────────────────────────────────────────────────

// TestEscrowSplitCommitment_VerifyGateOrdering asserts threshold
// bounds are checked before length and on-curve. A degenerate M=0
// produces ErrEscrowCommitmentThresholdBounds, not a downstream
// sentinel.
func TestEscrowSplitCommitment_VerifyGateOrdering(t *testing.T) {
	_, nonce, _ := canonicalEscrowFixture(t)
	c := buildSyntheticEscrowCommitment(t, 3, 5)
	c.M = 0
	c.CommitmentSet = nil
	err := VerifyEscrowSplitCommitment(&c, nonce)
	if !errors.Is(err, ErrEscrowCommitmentThresholdBounds) {
		t.Fatalf("want ErrEscrowCommitmentThresholdBounds first, got %v", err)
	}
}
