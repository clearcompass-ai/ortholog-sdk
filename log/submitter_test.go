package log

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// ─────────────────────────────────────────────────────────────────────
// Required-field validation
// ─────────────────────────────────────────────────────────────────────

func TestNewHTTPSubmitter_RequiresBaseURL(t *testing.T) {
	_, err := NewHTTPSubmitter(HTTPSubmitterConfig{})
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "BaseURL") {
		t.Fatalf("got %v, want ErrInvalidConfig + BaseURL", err)
	}
}

func TestNewHTTPSubmitter_RequiresLogDID(t *testing.T) {
	_, err := NewHTTPSubmitter(HTTPSubmitterConfig{BaseURL: "http://x"})
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "LogDID") {
		t.Fatalf("got %v, want ErrInvalidConfig + LogDID", err)
	}
}

func TestNewHTTPSubmitter_RequiresOperatorDID(t *testing.T) {
	_, err := NewHTTPSubmitter(HTTPSubmitterConfig{
		BaseURL: "http://x", LogDID: "did:key:zL",
	})
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "OperatorDID") {
		t.Fatalf("got %v, want ErrInvalidConfig + OperatorDID", err)
	}
}

func TestNewHTTPSubmitter_RequiresSignerDID(t *testing.T) {
	op, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	_, err = NewHTTPSubmitter(HTTPSubmitterConfig{
		BaseURL: "http://x", LogDID: "did:key:zL", OperatorDID: op.DID,
	})
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "SignerDID") {
		t.Fatalf("got %v, want ErrInvalidConfig + SignerDID", err)
	}
}

func TestNewHTTPSubmitter_RequiresPrivateKey(t *testing.T) {
	op, _ := did.GenerateDIDKeySecp256k1()
	sg, _ := did.GenerateDIDKeySecp256k1()
	_, err := NewHTTPSubmitter(HTTPSubmitterConfig{
		BaseURL: "http://x", LogDID: "did:key:zL",
		OperatorDID: op.DID, SignerDID: sg.DID,
	})
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "PrivateKey") {
		t.Fatalf("got %v, want ErrInvalidConfig + PrivateKey", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// OperatorDID resolution failures
// ─────────────────────────────────────────────────────────────────────

func TestNewHTTPSubmitter_OperatorDIDMalformed(t *testing.T) {
	sg, _ := did.GenerateDIDKeySecp256k1()
	_, err := NewHTTPSubmitter(HTTPSubmitterConfig{
		BaseURL:     "http://x",
		LogDID:      "did:key:zL",
		OperatorDID: "not-a-valid-did",
		SignerDID:   sg.DID,
		PrivateKey:  sg.PrivateKey,
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("got %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "resolve OperatorDID") {
		t.Fatalf("err should mention resolution: %v", err)
	}
}

func TestNewHTTPSubmitter_OperatorDIDIsEd25519(t *testing.T) {
	// Ed25519 did:key resolves through the ECDSA path with a clear
	// rejection — must surface as ErrInvalidConfig.
	ed, err := did.GenerateDIDKeyEd25519()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	sg, _ := did.GenerateDIDKeySecp256k1()
	_, err = NewHTTPSubmitter(HTTPSubmitterConfig{
		BaseURL:     "http://x",
		LogDID:      "did:key:zL",
		OperatorDID: ed.DID,
		SignerDID:   sg.DID,
		PrivateKey:  sg.PrivateKey,
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("got %v, want ErrInvalidConfig", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Default-application
// ─────────────────────────────────────────────────────────────────────

func TestNewHTTPSubmitter_DefaultsApplied(t *testing.T) {
	op, _ := did.GenerateDIDKeySecp256k1()
	sg, _ := did.GenerateDIDKeySecp256k1()
	s, err := NewHTTPSubmitter(HTTPSubmitterConfig{
		BaseURL:     "http://x",
		LogDID:      "did:key:zL",
		OperatorDID: op.DID,
		SignerDID:   sg.DID,
		PrivateKey:  sg.PrivateKey,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if s.cfg.EpochWindowSec != defaultEpochWindowSec {
		t.Errorf("EpochWindowSec=%d, want %d", s.cfg.EpochWindowSec, defaultEpochWindowSec)
	}
	if s.cfg.EpochAcceptanceWindow != defaultEpochAcceptanceWindow {
		t.Errorf("EpochAcceptanceWindow=%d", s.cfg.EpochAcceptanceWindow)
	}
	if s.cfg.DifficultyCacheTTL != defaultDifficultyCacheTTL {
		t.Errorf("DifficultyCacheTTL=%v", s.cfg.DifficultyCacheTTL)
	}
	if s.cfg.Timeout != defaultSubmitTimeout {
		t.Errorf("Timeout=%v", s.cfg.Timeout)
	}
	if s.cfg.PoWCheckInterval != defaultPoWCheckInterval {
		t.Errorf("PoWCheckInterval=%d", s.cfg.PoWCheckInterval)
	}
	if s.cfg.PoWMaxIterations != defaultPoWMaxIterations {
		t.Errorf("PoWMaxIterations=%d", s.cfg.PoWMaxIterations)
	}
	if s.client == nil {
		t.Error("client unset")
	}
	if s.operatorPub == nil {
		t.Error("operatorPub unset")
	}
}

func TestNewHTTPSubmitter_CustomClientHonored(t *testing.T) {
	op, _ := did.GenerateDIDKeySecp256k1()
	sg, _ := did.GenerateDIDKeySecp256k1()
	custom := DefaultClient(2 * time.Second)
	s, err := NewHTTPSubmitter(HTTPSubmitterConfig{
		BaseURL:     "http://x",
		LogDID:      "did:key:zL",
		OperatorDID: op.DID,
		SignerDID:   sg.DID,
		PrivateKey:  sg.PrivateKey,
		Client:      custom,
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if s.client != custom {
		t.Error("custom Client not used")
	}
}

func TestNewHTTPSubmitter_NegativeTimeoutDisablesCap(t *testing.T) {
	op, _ := did.GenerateDIDKeySecp256k1()
	sg, _ := did.GenerateDIDKeySecp256k1()
	s, err := NewHTTPSubmitter(HTTPSubmitterConfig{
		BaseURL:     "http://x",
		LogDID:      "did:key:zL",
		OperatorDID: op.DID,
		SignerDID:   sg.DID,
		PrivateKey:  sg.PrivateKey,
		Timeout:     -1, // disable cap
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if s.client.Timeout != 0 {
		t.Errorf("Timeout=%v, want 0 for disabled", s.client.Timeout)
	}
}

// ─────────────────────────────────────────────────────────────────────
// modeIsAuthenticated dispatch
// ─────────────────────────────────────────────────────────────────────

func TestNewHTTPSubmitter_ModeDispatch(t *testing.T) {
	op, _ := did.GenerateDIDKeySecp256k1()
	sg, _ := did.GenerateDIDKeySecp256k1()
	cfg := HTTPSubmitterConfig{
		BaseURL: "http://x", LogDID: "did:key:zL",
		OperatorDID: op.DID, SignerDID: sg.DID, PrivateKey: sg.PrivateKey,
	}
	noTok, _ := NewHTTPSubmitter(cfg)
	if noTok.modeIsAuthenticated() {
		t.Error("empty AuthToken should be Mode B")
	}
	cfg.AuthToken = "tok"
	withTok, _ := NewHTTPSubmitter(cfg)
	if !withTok.modeIsAuthenticated() {
		t.Error("non-empty AuthToken should be Mode A")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Type-shape pins (catch silent renames in struct fields)
// ─────────────────────────────────────────────────────────────────────

func TestTypes_FieldShapes(t *testing.T) {
	_ = HTTPSubmitterConfig{
		BaseURL: "x", LogDID: "y", OperatorDID: "z",
		SignerDID: "s", AuthToken: "tok",
		EpochWindowSec: 1, EpochAcceptanceWindow: 1,
		DifficultyCacheTTL: time.Second, Timeout: time.Second,
		PoWCheckInterval: 1, PoWMaxIterations: 1,
	}
	_ = SubmitItem{Payload: []byte{1}}
	e := &HTTPError{StatusCode: 500, Body: "x"}
	if !strings.Contains(e.Error(), "500") {
		t.Errorf("HTTPError.Error: %s", e.Error())
	}
	// Sentinels addressable
	for _, err := range []error{
		ErrInvalidConfig, ErrUnauthorized, ErrInsufficientCredits,
		ErrStampRejected, ErrDuplicateEntry, ErrEntryTooLarge,
		ErrValidation, ErrServiceUnavailable, ErrSCTRejected,
		ErrBatchEmpty, ErrBatchTooLarge, ErrBatchResultMismatch,
		ErrPoWExhausted,
	} {
		if err == nil {
			t.Error("nil sentinel")
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Constants pinned
// ─────────────────────────────────────────────────────────────────────

func TestConstants_Pinned(t *testing.T) {
	if MaxBatchSize != 256 {
		t.Errorf("MaxBatchSize=%d, want 256 (must match operator)", MaxBatchSize)
	}
}
