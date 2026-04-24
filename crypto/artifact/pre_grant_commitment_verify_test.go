package artifact

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// ─────────────────────────────────────────────────────────────────────
// Happy path — baseline for the per-gate mutation tests below
// ─────────────────────────────────────────────────────────────────────

// TestPREGrantCommitment_VerifyHappyPath confirms Verify returns nil
// on a well-formed commitment bound to its canonical (grantor,
// recipient, artifact) fixture.
func TestPREGrantCommitment_VerifyHappyPath(t *testing.T) {
	grantor, recipient, cid, _ := canonicalPREFixture(t)
	c := buildSyntheticCommitment(t, 3, 5)
	if err := VerifyPREGrantCommitment(&c, grantor, recipient, cid); err != nil {
		t.Fatalf("Verify happy path: %v", err)
	}
}

// TestPREGrantCommitment_VerifyNil rejects a nil commitment.
func TestPREGrantCommitment_VerifyNil(t *testing.T) {
	grantor, recipient, cid, _ := canonicalPREFixture(t)
	if err := VerifyPREGrantCommitment(nil, grantor, recipient, cid); !errors.Is(err, ErrCommitmentSetLength) {
		t.Fatalf("want ErrCommitmentSetLength on nil, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableCommitmentOnCurveGate
// ─────────────────────────────────────────────────────────────────────

// TestPREGrantCommitment_VerifyRejectsOffCurvePoint pins that an
// off-curve point in CommitmentSet is rejected at Verify time. Binds
// the muEnableCommitmentOnCurveGate mutation switch: flipping it
// false would allow the off-curve point to pass the on-curve gate
// (the remaining gates do not check point validity, so the SplitID
// gate would then pass and Verify would silently accept).
func TestPREGrantCommitment_VerifyRejectsOffCurvePoint(t *testing.T) {
	grantor, recipient, cid, _ := canonicalPREFixture(t)
	c := buildSyntheticCommitment(t, 3, 5)
	// Overwrite one point with 0x02 || 0x00...00 — on-curve check
	// fails because (0, y) with y²=7 has no root in F_p.
	for i := range c.CommitmentSet[1] {
		c.CommitmentSet[1][i] = 0
	}
	c.CommitmentSet[1][0] = 0x02
	if err := VerifyPREGrantCommitment(&c, grantor, recipient, cid); !errors.Is(err, ErrCommitmentPointOffCurve) {
		t.Fatalf("want ErrCommitmentPointOffCurve, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableCommitmentSetLengthCheck
// ─────────────────────────────────────────────────────────────────────

// TestPREGrantCommitment_VerifyRejectsShortCommitmentSet asserts that
// len(CommitmentSet) < M is rejected at Verify. Binds
// muEnableCommitmentSetLengthCheck.
func TestPREGrantCommitment_VerifyRejectsShortCommitmentSet(t *testing.T) {
	grantor, recipient, cid, _ := canonicalPREFixture(t)
	c := buildSyntheticCommitment(t, 3, 5)
	c.CommitmentSet = c.CommitmentSet[:2]
	if err := VerifyPREGrantCommitment(&c, grantor, recipient, cid); !errors.Is(err, ErrCommitmentSetLength) {
		t.Fatalf("want ErrCommitmentSetLength, got %v", err)
	}
}

// TestPREGrantCommitment_VerifyRejectsLongCommitmentSet asserts that
// len(CommitmentSet) > M is rejected at Verify. Binds
// muEnableCommitmentSetLengthCheck.
func TestPREGrantCommitment_VerifyRejectsLongCommitmentSet(t *testing.T) {
	grantor, recipient, cid, _ := canonicalPREFixture(t)
	c := buildSyntheticCommitment(t, 3, 5)
	c.CommitmentSet = append(c.CommitmentSet, syntheticCompressedPoint(t, 4))
	if err := VerifyPREGrantCommitment(&c, grantor, recipient, cid); !errors.Is(err, ErrCommitmentSetLength) {
		t.Fatalf("want ErrCommitmentSetLength, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableThresholdBoundsCheck
// ─────────────────────────────────────────────────────────────────────

// TestPREGrantCommitment_VerifyRejectsThresholdBelowMin covers M=0
// and M=1. Binds muEnableThresholdBoundsCheck.
func TestPREGrantCommitment_VerifyRejectsThresholdBelowMin(t *testing.T) {
	grantor, recipient, cid, _ := canonicalPREFixture(t)
	// M=1: a 1-of-N split is not a threshold scheme.
	c := buildSyntheticCommitment(t, 2, 5)
	c.M = 1
	if err := VerifyPREGrantCommitment(&c, grantor, recipient, cid); !errors.Is(err, ErrCommitmentThresholdBounds) {
		t.Fatalf("M=1: want ErrCommitmentThresholdBounds, got %v", err)
	}
	// M=0.
	c.M = 0
	if err := VerifyPREGrantCommitment(&c, grantor, recipient, cid); !errors.Is(err, ErrCommitmentThresholdBounds) {
		t.Fatalf("M=0: want ErrCommitmentThresholdBounds, got %v", err)
	}
}

// TestPREGrantCommitment_VerifyRejectsMAboveN asserts M > N is
// rejected. Binds muEnableThresholdBoundsCheck.
func TestPREGrantCommitment_VerifyRejectsMAboveN(t *testing.T) {
	grantor, recipient, cid, _ := canonicalPREFixture(t)
	c := buildSyntheticCommitment(t, 5, 3) // caller-requested M>N via override
	c.M = 5
	c.N = 3
	if err := VerifyPREGrantCommitment(&c, grantor, recipient, cid); !errors.Is(err, ErrCommitmentThresholdBounds) {
		t.Fatalf("want ErrCommitmentThresholdBounds, got %v", err)
	}
}

// TestPREGrantCommitment_VerifyRejectsNZero asserts N=0 is rejected.
// Binds muEnableThresholdBoundsCheck.
func TestPREGrantCommitment_VerifyRejectsNZero(t *testing.T) {
	grantor, recipient, cid, _ := canonicalPREFixture(t)
	c := buildSyntheticCommitment(t, 2, 2)
	c.N = 0
	if err := VerifyPREGrantCommitment(&c, grantor, recipient, cid); !errors.Is(err, ErrCommitmentThresholdBounds) {
		t.Fatalf("want ErrCommitmentThresholdBounds, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableSplitIDRecomputation — four independent tests, one
// per input-tuple component plus one for a direct SplitID tamper
// ─────────────────────────────────────────────────────────────────────

// TestPREGrantCommitment_VerifyRejectsWrongSplitID asserts that a
// tampered SplitID (any [32]byte that is not ComputePREGrantSplitID
// of the supplied tuple) is rejected. Binds
// muEnableSplitIDRecomputation.
func TestPREGrantCommitment_VerifyRejectsWrongSplitID(t *testing.T) {
	grantor, recipient, cid, _ := canonicalPREFixture(t)
	c := buildSyntheticCommitment(t, 3, 5)
	// Flip the first byte of the SplitID.
	c.SplitID[0] ^= 0x01
	if err := VerifyPREGrantCommitment(&c, grantor, recipient, cid); !errors.Is(err, ErrCommitmentSplitIDMismatch) {
		t.Fatalf("want ErrCommitmentSplitIDMismatch, got %v", err)
	}
}

// TestPREGrantCommitment_VerifyRejectsWrongGrantor asserts that
// calling Verify with a grantor that differs from the one baked
// into SplitID is rejected. Binds muEnableSplitIDRecomputation.
func TestPREGrantCommitment_VerifyRejectsWrongGrantor(t *testing.T) {
	_, recipient, cid, _ := canonicalPREFixture(t)
	c := buildSyntheticCommitment(t, 3, 5)
	if err := VerifyPREGrantCommitment(&c, "did:web:attacker.example.com", recipient, cid); !errors.Is(err, ErrCommitmentSplitIDMismatch) {
		t.Fatalf("want ErrCommitmentSplitIDMismatch, got %v", err)
	}
}

// TestPREGrantCommitment_VerifyRejectsWrongRecipient asserts that
// calling Verify with a recipient that differs from the one baked
// into SplitID is rejected. Binds muEnableSplitIDRecomputation.
func TestPREGrantCommitment_VerifyRejectsWrongRecipient(t *testing.T) {
	grantor, _, cid, _ := canonicalPREFixture(t)
	c := buildSyntheticCommitment(t, 3, 5)
	if err := VerifyPREGrantCommitment(&c, grantor, "did:web:wrong-recipient.example.com", cid); !errors.Is(err, ErrCommitmentSplitIDMismatch) {
		t.Fatalf("want ErrCommitmentSplitIDMismatch, got %v", err)
	}
}

// TestPREGrantCommitment_VerifyRejectsWrongCID asserts that calling
// Verify with a CID that differs from the one baked into SplitID is
// rejected. Binds muEnableSplitIDRecomputation.
func TestPREGrantCommitment_VerifyRejectsWrongCID(t *testing.T) {
	grantor, recipient, _, _ := canonicalPREFixture(t)
	c := buildSyntheticCommitment(t, 3, 5)
	other := sha256.Sum256([]byte("different-artifact"))
	wrongCID := storage.CID{Algorithm: storage.AlgoSHA256, Digest: other[:]}
	if err := VerifyPREGrantCommitment(&c, grantor, recipient, wrongCID); !errors.Is(err, ErrCommitmentSplitIDMismatch) {
		t.Fatalf("want ErrCommitmentSplitIDMismatch, got %v", err)
	}
}

// TestPREGrantCommitment_VerifyRejectsAlgorithmSwap pins that a CID
// with the same 32-byte digest under a different algorithm tag
// produces a different SplitID and therefore fails Verify. This
// mirrors the storage-layer cross-algorithm collision-resistance
// guarantee at the commitment-entry layer.
func TestPREGrantCommitment_VerifyRejectsAlgorithmSwap(t *testing.T) {
	grantor, recipient, _, _ := canonicalPREFixture(t)
	// Register a distinct algorithm tag sharing the SHA-256 digest
	// size. The test-local RegisterAlgorithm is idempotent across
	// test runs but the tag must be unique within the package test
	// binary — 0xF3 is unused elsewhere in this file.
	const cidAlgoSwap storage.HashAlgorithm = 0xF3
	storage.RegisterAlgorithm(cidAlgoSwap, "pre-grant-commitment-algo-swap", 32, func(data []byte) []byte {
		h := sha256.Sum256(data)
		return h[:]
	})

	// Use the canonical "artifact/1" digest under the new algorithm.
	dig := sha256.Sum256([]byte("artifact/1"))
	wrongCID := storage.CID{Algorithm: cidAlgoSwap, Digest: dig[:]}

	c := buildSyntheticCommitment(t, 3, 5)
	if err := VerifyPREGrantCommitment(&c, grantor, recipient, wrongCID); !errors.Is(err, ErrCommitmentSplitIDMismatch) {
		t.Fatalf("want ErrCommitmentSplitIDMismatch on algo-swap, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Defense-in-depth: gate ordering
// ─────────────────────────────────────────────────────────────────────

// TestPREGrantCommitment_VerifyGateOrdering asserts threshold bounds
// are checked before length and on-curve — a degenerate M=0 produces
// ErrCommitmentThresholdBounds not one of the downstream sentinels.
// Pins the documented gate order in VerifyPREGrantCommitment.
func TestPREGrantCommitment_VerifyGateOrdering(t *testing.T) {
	grantor, recipient, cid, _ := canonicalPREFixture(t)
	c := buildSyntheticCommitment(t, 3, 5)
	// Break both threshold bounds and commitment-set length at once.
	// The threshold-bounds gate must fire first.
	c.M = 0
	c.CommitmentSet = nil
	err := VerifyPREGrantCommitment(&c, grantor, recipient, cid)
	if !errors.Is(err, ErrCommitmentThresholdBounds) {
		t.Fatalf("want ErrCommitmentThresholdBounds first (gate order), got %v", err)
	}
}
