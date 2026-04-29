package log

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// prepareHeader
// ─────────────────────────────────────────────────────────────────────

func TestPrepareHeader_AutoFillsZero(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "")
	in := envelope.ControlHeader{}
	out := s.prepareHeader(in)
	if out.Destination != defaultTestLogDID {
		t.Errorf("Destination=%q", out.Destination)
	}
	if out.SignerDID != s.cfg.SignerDID {
		t.Errorf("SignerDID=%q", out.SignerDID)
	}
	if out.EventTime <= 0 {
		t.Errorf("EventTime=%d, want >0", out.EventTime)
	}
	// EventTime must be in microseconds — within last 10s of "now"
	// in micros.
	now := time.Now().UTC().UnixMicro()
	if delta := now - out.EventTime; delta < 0 || delta > int64(10*time.Second/time.Microsecond) {
		t.Errorf("EventTime=%d not within 10s of now=%d (delta=%d)", out.EventTime, now, delta)
	}
}

func TestPrepareHeader_NonZeroPreserved(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "")
	in := envelope.ControlHeader{
		Destination: "did:key:zCustom",
		SignerDID:   "did:key:zSigner",
		EventTime:   1234567890,
	}
	out := s.prepareHeader(in)
	if out.Destination != "did:key:zCustom" {
		t.Errorf("Destination overwritten")
	}
	if out.SignerDID != "did:key:zSigner" {
		t.Errorf("SignerDID overwritten")
	}
	if out.EventTime != 1234567890 {
		t.Errorf("EventTime overwritten")
	}
}

// ─────────────────────────────────────────────────────────────────────
// signAndSerialize
// ─────────────────────────────────────────────────────────────────────

func TestSignAndSerialize_HappyPath(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "")
	header := s.prepareHeader(envelope.ControlHeader{})
	entry, err := envelope.NewUnsignedEntry(header, []byte("payload"))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	wire, err := s.signAndSerialize(entry)
	if err != nil {
		t.Fatalf("signAndSerialize: %v", err)
	}

	// Round-trip deserialize.
	got, err := envelope.Deserialize(wire)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if len(got.Signatures) != 1 {
		t.Fatalf("sigs=%d, want 1", len(got.Signatures))
	}
	if got.Signatures[0].SignerDID != s.cfg.SignerDID {
		t.Errorf("Signatures[0].SignerDID=%q", got.Signatures[0].SignerDID)
	}
	if got.Signatures[0].AlgoID != envelope.SigAlgoECDSA {
		t.Errorf("AlgoID=%d", got.Signatures[0].AlgoID)
	}

	// Signature actually verifies against the submitter's pubkey.
	signingHash := sha256.Sum256(envelope.SigningPayload(got))
	if err := signatures.VerifyEntry(signingHash, got.Signatures[0].Bytes,
		&op.submitterKP.PrivateKey.PublicKey); err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// buildModeA
// ─────────────────────────────────────────────────────────────────────

func TestBuildModeA_HappyPath(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "tok")
	wire, err := s.buildModeA(envelope.ControlHeader{}, []byte("hello"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	got, err := envelope.Deserialize(wire)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.Header.AdmissionProof != nil {
		t.Error("Mode A wire must NOT carry AdmissionProof")
	}
}

func TestBuildModeA_StripsCallerSuppliedProof(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "tok")
	header := envelope.ControlHeader{
		AdmissionProof: &envelope.AdmissionProofBody{
			Mode:       types.WireByteModeB,
			Difficulty: 99,
		},
	}
	wire, err := s.buildModeA(header, []byte("x"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	got, _ := envelope.Deserialize(wire)
	if got.Header.AdmissionProof != nil {
		t.Error("Mode A must strip caller-supplied AdmissionProof")
	}
}

// ─────────────────────────────────────────────────────────────────────
// buildModeB
// ─────────────────────────────────────────────────────────────────────

func TestBuildModeB_HappyPathLowDifficulty(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "")

	wire, err := s.buildModeB(context.Background(),
		envelope.ControlHeader{}, []byte("hi"), 4, "sha256")
	if err != nil {
		t.Fatalf("buildModeB: %v", err)
	}
	got, err := envelope.Deserialize(wire)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.Header.AdmissionProof == nil {
		t.Fatal("Mode B wire must carry AdmissionProof")
	}
	if got.Header.AdmissionProof.Mode != types.WireByteModeB {
		t.Errorf("Mode=%d, want ModeB", got.Header.AdmissionProof.Mode)
	}
	if got.Header.AdmissionProof.Difficulty != 4 {
		t.Errorf("Difficulty=%d, want 4", got.Header.AdmissionProof.Difficulty)
	}
}

func TestBuildModeB_CancelledCtx(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "")
	// Use very high difficulty so PoW would take a long time, AND
	// PoWCheckInterval=1 so cancellation hits on first iteration.
	s.cfg.PoWCheckInterval = 1
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.buildModeB(ctx, envelope.ControlHeader{}, []byte("x"), 64, "sha256")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestBuildModeB_ExhaustionReturnsErr(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "")
	// Cap PoWMaxIterations at 4 with difficulty 64 — the search
	// space is overwhelmingly likely to be exhausted within 4
	// iterations at d=64 (probability ~1 - 2^-256, effectively 1).
	s.cfg.PoWMaxIterations = 4
	s.cfg.PoWCheckInterval = 256
	_, err := s.buildModeB(context.Background(),
		envelope.ControlHeader{}, []byte("x"), 64, "sha256")
	if !errors.Is(err, ErrPoWExhausted) {
		t.Fatalf("got %v, want ErrPoWExhausted", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// buildOne dispatch
// ─────────────────────────────────────────────────────────────────────

func TestBuildOne_DispatchesModeA(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "tok")
	wire, err := s.buildOne(context.Background(),
		envelope.ControlHeader{}, []byte("x"), 4, "sha256")
	if err != nil {
		t.Fatalf("%v", err)
	}
	got, _ := envelope.Deserialize(wire)
	if got.Header.AdmissionProof != nil {
		t.Error("buildOne with token must produce Mode A (no AdmissionProof)")
	}
}

func TestBuildOne_DispatchesModeB(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "")
	wire, err := s.buildOne(context.Background(),
		envelope.ControlHeader{}, []byte("x"), 4, "sha256")
	if err != nil {
		t.Fatalf("%v", err)
	}
	got, _ := envelope.Deserialize(wire)
	if got.Header.AdmissionProof == nil {
		t.Error("buildOne without token must produce Mode B (with AdmissionProof)")
	}
}
