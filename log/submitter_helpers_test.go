package log

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/sct"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// ─────────────────────────────────────────────────────────────────────
// testOperator
// ─────────────────────────────────────────────────────────────────────

// testOperator simulates the operator's HTTP surface for submitter
// tests. Routes are swappable via SetDifficultyHandler /
// SetSubmitHandler / SetBatchHandler so each test customizes only
// the behavior it needs.
type testOperator struct {
	srv         *httptest.Server
	operatorKP  *did.DIDKeyPairSecp256k1
	submitterKP *did.DIDKeyPairSecp256k1

	mu                sync.Mutex
	difficultyCount   int
	submitCount       int
	batchCount        int
	currentDifficulty uint32
	currentHashFunc   string

	// Default handlers — tests override before the server receives
	// its first request.
	difficultyHandler http.HandlerFunc
	submitHandler     http.HandlerFunc
	batchHandler      http.HandlerFunc
}

// newTestOperator generates fresh operator + submitter keypairs
// and stands up an httptest.Server with default routes that
// produce a successful submission flow (difficulty=4 SHA-256, 202
// + signed SCT).
func newTestOperator(t *testing.T) *testOperator {
	t.Helper()
	operatorKP, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("generate operator key: %v", err)
	}
	submitterKP, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("generate submitter key: %v", err)
	}
	op := &testOperator{
		operatorKP:        operatorKP,
		submitterKP:       submitterKP,
		currentDifficulty: 4,
		currentHashFunc:   "sha256",
	}
	op.difficultyHandler = op.defaultDifficultyHandler
	op.submitHandler = op.defaultSubmitHandler
	op.batchHandler = op.defaultBatchHandler

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/admission/difficulty", func(w http.ResponseWriter, r *http.Request) {
		op.mu.Lock()
		op.difficultyCount++
		h := op.difficultyHandler
		op.mu.Unlock()
		h(w, r)
	})
	mux.HandleFunc("/v1/entries", func(w http.ResponseWriter, r *http.Request) {
		op.mu.Lock()
		op.submitCount++
		h := op.submitHandler
		op.mu.Unlock()
		h(w, r)
	})
	mux.HandleFunc("/v1/entries/batch", func(w http.ResponseWriter, r *http.Request) {
		op.mu.Lock()
		op.batchCount++
		h := op.batchHandler
		op.mu.Unlock()
		h(w, r)
	})

	op.srv = httptest.NewServer(mux)
	t.Cleanup(op.srv.Close)
	return op
}

// SetDifficulty rewrites the operator's reported difficulty for
// future GET /v1/admission/difficulty calls.
func (o *testOperator) SetDifficulty(d uint32, hashFunc string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.currentDifficulty = d
	o.currentHashFunc = hashFunc
}

// DifficultyCount returns how many times the difficulty endpoint
// has been hit. Used to assert cache behavior.
func (o *testOperator) DifficultyCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.difficultyCount
}

// SetSubmitHandler swaps in a custom submit-route handler for the
// duration of a test.
func (o *testOperator) SetSubmitHandler(h http.HandlerFunc) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.submitHandler = h
}

// SetDifficultyHandler swaps in a custom difficulty-route handler.
func (o *testOperator) SetDifficultyHandler(h http.HandlerFunc) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.difficultyHandler = h
}

// SetBatchHandler swaps in a custom batch-route handler.
func (o *testOperator) SetBatchHandler(h http.HandlerFunc) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.batchHandler = h
}

// ─────────────────────────────────────────────────────────────────────
// Default handlers
// ─────────────────────────────────────────────────────────────────────

func (o *testOperator) defaultDifficultyHandler(w http.ResponseWriter, _ *http.Request) {
	o.mu.Lock()
	d := o.currentDifficulty
	h := o.currentHashFunc
	o.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"difficulty":    d,
		"hash_function": h,
	})
}

func (o *testOperator) defaultSubmitHandler(w http.ResponseWriter, r *http.Request) {
	wire, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if len(wire) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	canonicalHash := sha256.Sum256(wire)
	logTime := time.Now().UTC().Truncate(time.Microsecond)
	scTok, err := o.signSCT(canonicalHash, logTime, defaultTestLogDID)
	if err != nil {
		http.Error(w, "sign sct: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(scTok)
}

func (o *testOperator) defaultBatchHandler(w http.ResponseWriter, r *http.Request) {
	var req batchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "parse: "+err.Error(), http.StatusBadRequest)
		return
	}
	out := batchResponse{Results: make([]batchResultWire, len(req.Entries))}
	for i, e := range req.Entries {
		wire, err := hex.DecodeString(e.WireBytesHex)
		if err != nil {
			http.Error(w, "hex decode", http.StatusBadRequest)
			return
		}
		canonicalHash := sha256.Sum256(wire)
		logTime := time.Now().UTC().Truncate(time.Microsecond)
		scTok, err := o.signSCT(canonicalHash, logTime, defaultTestLogDID)
		if err != nil {
			http.Error(w, "sign sct: "+err.Error(), http.StatusInternalServerError)
			return
		}
		out.Results[i] = batchResultWire{SCT: *scTok}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(out)
}

// ─────────────────────────────────────────────────────────────────────
// SCT minting (operator-side)
// ─────────────────────────────────────────────────────────────────────

// signSCT mints a valid SignedCertificateTimestamp for the given
// canonical hash + log time using the test operator's private key.
// Routes through the SDK's sct.SigningPayload so any byte-layout
// change in the SDK breaks tests immediately rather than silently
// producing SCTs that no longer verify.
func (o *testOperator) signSCT(
	canonicalHash [32]byte,
	logTime time.Time,
	logDID string,
) (*sct.SignedCertificateTimestamp, error) {
	logTimeMicros := logTime.UnixMicro()
	payload, err := sct.SigningPayload(o.operatorKP.DID,
		sct.SigAlgoECDSASecp256k1SHA256, logDID, canonicalHash, logTimeMicros)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	sig, err := signatures.SignEntry(digest, o.operatorKP.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &sct.SignedCertificateTimestamp{
		Version:       sct.Version,
		SignerDID:     o.operatorKP.DID,
		SigAlgoID:     sct.SigAlgoECDSASecp256k1SHA256,
		LogDID:        logDID,
		CanonicalHash: hex.EncodeToString(canonicalHash[:]),
		LogTimeMicros: logTimeMicros,
		LogTime:       time.UnixMicro(logTimeMicros).UTC().Format(time.RFC3339Nano),
		Signature:     hex.EncodeToString(sig),
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// Submitter factory
// ─────────────────────────────────────────────────────────────────────

const defaultTestLogDID = "did:key:zTestLog"

// newTestSubmitter constructs an HTTPSubmitter wired against op
// with sensible defaults for fast tests:
//   - PoWMaxIterations = 1<<20 (caps runaway PoW in failing tests)
//   - DifficultyCacheTTL = 1h (so cache stays warm across the test)
//   - Client = op.srv.Client() (httptest's transport)
//
// authToken empty → Mode B; non-empty → Mode A.
func newTestSubmitter(t *testing.T, op *testOperator, authToken string) *HTTPSubmitter {
	t.Helper()
	s, err := NewHTTPSubmitter(HTTPSubmitterConfig{
		BaseURL:               op.srv.URL,
		LogDID:                defaultTestLogDID,
		OperatorDID:           op.operatorKP.DID,
		SignerDID:             op.submitterKP.DID,
		PrivateKey:            op.submitterKP.PrivateKey,
		AuthToken:             authToken,
		EpochWindowSec:        300,
		EpochAcceptanceWindow: 1,
		DifficultyCacheTTL:    time.Hour,
		Timeout:               5 * time.Second,
		Client:                op.srv.Client(),
		PoWCheckInterval:      256,
		PoWMaxIterations:      1 << 20,
	})
	if err != nil {
		t.Fatalf("newTestSubmitter: %v", err)
	}
	return s
}
