/*
Package log — submitter.go declares HTTPSubmitter, the SDK's
production HTTP client for entry admission against the operator's
POST /v1/entries and POST /v1/entries/batch endpoints.

Why this exists:

	The previous submission story was hand-rolled HTTP plus inline
	byte-shifting (cmd/submit-stamp/main.go, ~330 lines per call
	site). Every consumer reinvented Mode A/B dispatch, PoW
	iteration, SCT verification, retry, and connection-pool tuning
	— badly. HTTPSubmitter centralizes the contract so consumers
	call Submit(ctx, header, payload) and get back a verified
	*sct.SignedCertificateTimestamp or a typed error.

Concurrency:

	Goroutine-safe. Multiple goroutines may call Submit and
	SubmitBatch concurrently against the same submitter. The
	difficulty cache uses sync.RWMutex; cfg, client, and
	operatorPub are read-only post-construction.

File layout (each <300 lines, one concern):

	submitter.go             — types, errors, constructor (this file)
	submitter_build.go       — Mode A/B wire builders + PoW loop
	submitter_difficulty.go  — difficulty cache + GET /v1/admission/difficulty
	submitter_submit.go      — Submit() + 403 cache-bust retry + SCT verify
	submitter_batch.go       — SubmitBatch() + JSON wire encoding
	submitter_status.go      — HTTP status mapping + drainAndClose

Cross-file invariants:

	- Every HTTP response is run through drainAndClose (defined in
	  submitter_status.go) so HTTP/2 streams are properly released
	  even on parse error. This is the load-bearing fix against
	  "stream is idle" / INTERNAL_ERROR pile-ups under load.
	- Every request body is *bytes.Reader so stdlib auto-populates
	  req.GetBody for the RetryAfterRoundTripper's 503 replay path.
	- Every public method takes ctx and propagates it via
	  http.NewRequestWithContext.
*/
package log

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// ─────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────

// MaxBatchSize mirrors ortholog-operator/api/batch.go::MaxBatchSize.
// Operator rejects batches larger than this with HTTP 400; the
// submitter validates locally to fail fast before consuming a
// network round-trip.
const MaxBatchSize = 256

// Default config values. Exposed as constants so tests and
// observability tooling can pin against the same numbers.
const (
	defaultEpochWindowSec        uint64 = 300
	defaultEpochAcceptanceWindow uint64 = 1
	defaultDifficultyCacheTTL           = 10 * time.Minute
	defaultSubmitTimeout                = 60 * time.Second
	defaultPoWCheckInterval             = 4096
	defaultPoWMaxIterations      uint64 = 1 << 30
)

// ─────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────

// HTTPSubmitterConfig configures HTTPSubmitter. All fields except
// the ones marked optional are required; NewHTTPSubmitter rejects
// missing values with ErrInvalidConfig.
type HTTPSubmitterConfig struct {
	// BaseURL is the operator's base URL with no trailing slash
	// (e.g., "https://operator.example.com").
	BaseURL string

	// LogDID identifies the destination log. Used to auto-fill
	// entry.Header.Destination when callers leave it zero, and as
	// the TargetLog argument for VerifyStamp during PoW.
	LogDID string

	// OperatorDID is the operator's did:key:z... identifier.
	// Resolved at constructor time to *ecdsa.PublicKey so every
	// Submit call verifies SCTs without re-parsing the DID.
	OperatorDID string

	// SignerDID is this submitter's identifier. Auto-fills
	// entry.Header.SignerDID when callers leave it zero.
	SignerDID string

	// PrivateKey signs every entry produced by this submitter.
	// MUST correspond to SignerDID's published public key.
	PrivateKey *ecdsa.PrivateKey

	// AuthToken switches the submitter into Mode A. When set,
	// submissions include Authorization: Bearer <token> and skip
	// PoW. Empty → Mode B (proof-of-work stamp).
	AuthToken string

	// EpochWindowSec is the operator's Mode B epoch width in
	// seconds. Zero defaults to 300 (operator default per
	// crypto/admission/stamp.go::DefaultEpochWindowSeconds).
	EpochWindowSec uint64

	// EpochAcceptanceWindow is the tolerance in epochs the
	// submitter passes to local VerifyStamp self-check. Zero
	// defaults to 1.
	EpochAcceptanceWindow uint64

	// DifficultyCacheTTL caps how long the difficulty cache stays
	// valid. After TTL elapses the next Mode B submission
	// transparently re-fetches. Zero defaults to 10 minutes.
	DifficultyCacheTTL time.Duration

	// Timeout caps the total round-trip including 503-Retry-After
	// loops, applied to the wired *http.Client. Zero defaults to
	// 60s. Pass <0 to disable (request-context becomes the only
	// cap).
	Timeout time.Duration

	// Client overrides the HTTP client. nil → DefaultClient(Timeout)
	// which wires DefaultTransport + RetryAfterRoundTripper. Tests
	// pass an httptest-backed client here.
	Client *http.Client

	// PoWCheckInterval is how often the Mode B loop checks ctx.Err
	// to remain interruptible. Zero defaults to 4096 iterations
	// (~200µs at d=20 with sha256+secp256k1 signing).
	PoWCheckInterval int

	// PoWMaxIterations caps the PoW search to bound CPU. Zero
	// defaults to 1<<30 (≈1B iterations). Realistic searches at
	// d≤24 are far below this; the cap exists to prevent runaway
	// difficulty configurations from pinning a goroutine.
	PoWMaxIterations uint64
}

// ─────────────────────────────────────────────────────────────────────
// SubmitItem (batch input)
// ─────────────────────────────────────────────────────────────────────

// SubmitItem is one entry slot in a SubmitBatch call. The submitter
// auto-fills Destination/SignerDID/EventTime if zero, signs the
// entry, performs Mode B PoW if no AuthToken is set, and includes
// the resulting wire bytes in the batch JSON body.
type SubmitItem struct {
	Header  envelope.ControlHeader
	Payload []byte
}

// ─────────────────────────────────────────────────────────────────────
// HTTPSubmitter
// ─────────────────────────────────────────────────────────────────────

// HTTPSubmitter posts entries to the operator and returns verified
// SCTs. Goroutine-safe.
type HTTPSubmitter struct {
	cfg         HTTPSubmitterConfig
	client      *http.Client
	operatorPub *ecdsa.PublicKey

	diffMu sync.RWMutex
	diff   difficultyState
}

// difficultyState is the cached operator difficulty. Initialized to
// the zero value; the first Mode B submission triggers a lazy
// refresh via fetchDifficulty (submitter_difficulty.go).
type difficultyState struct {
	Difficulty  uint32
	HashFunc    string // "sha256" or "argon2id"
	FetchedAt   time.Time
	Initialized bool
}

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// HTTPError carries an unmapped HTTP status code and response body
// snippet. Returned by submit paths when the operator returns a
// status not covered by a typed sentinel.
type HTTPError struct {
	StatusCode int
	Body       string
}

// Error renders HTTPError for log output.
func (e *HTTPError) Error() string {
	return fmt.Sprintf("log/submitter: operator returned HTTP %d: %s", e.StatusCode, e.Body)
}

// Typed error sentinels. Callers errors.Is(err, ErrXxx) to dispatch
// without parsing strings.
var (
	ErrInvalidConfig       = errors.New("log/submitter: invalid configuration")
	ErrUnauthorized        = errors.New("log/submitter: unauthorized (HTTP 401)")
	ErrInsufficientCredits = errors.New("log/submitter: insufficient write credits (HTTP 402)")
	ErrStampRejected       = errors.New("log/submitter: Mode B stamp rejected (HTTP 403)")
	ErrDuplicateEntry      = errors.New("log/submitter: duplicate entry (HTTP 409)")
	ErrEntryTooLarge       = errors.New("log/submitter: entry too large (HTTP 413)")
	ErrValidation          = errors.New("log/submitter: entry validation failed (HTTP 422)")
	ErrServiceUnavailable  = errors.New("log/submitter: operator unavailable (HTTP 503 after retries)")
	ErrSCTRejected         = errors.New("log/submitter: SCT signature did not verify against operator key")

	ErrBatchEmpty          = errors.New("log/submitter: batch is empty")
	ErrBatchTooLarge       = errors.New("log/submitter: batch exceeds MaxBatchSize")
	ErrBatchResultMismatch = errors.New("log/submitter: batch result count mismatches request")
	ErrPoWExhausted        = errors.New("log/submitter: PoW nonce search exhausted PoWMaxIterations")
)

// ─────────────────────────────────────────────────────────────────────
// Constructor
// ─────────────────────────────────────────────────────────────────────

// NewHTTPSubmitter validates cfg, resolves OperatorDID to a public
// key, applies defaults, and returns a ready-to-use submitter. The
// returned value is goroutine-safe.
//
// Constructor errors (all wrap ErrInvalidConfig):
//   - BaseURL empty
//   - LogDID empty
//   - OperatorDID empty or unresolvable to *ecdsa.PublicKey
//   - SignerDID empty
//   - PrivateKey nil
func NewHTTPSubmitter(cfg HTTPSubmitterConfig) (*HTTPSubmitter, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("%w: BaseURL required", ErrInvalidConfig)
	}
	if cfg.LogDID == "" {
		return nil, fmt.Errorf("%w: LogDID required", ErrInvalidConfig)
	}
	if cfg.OperatorDID == "" {
		return nil, fmt.Errorf("%w: OperatorDID required", ErrInvalidConfig)
	}
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("%w: SignerDID required", ErrInvalidConfig)
	}
	if cfg.PrivateKey == nil {
		return nil, fmt.Errorf("%w: PrivateKey required", ErrInvalidConfig)
	}

	pub, err := did.NewECDSAKeyResolver().ResolvePublicKey(context.Background(), cfg.OperatorDID)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve OperatorDID: %v", ErrInvalidConfig, err)
	}

	if cfg.EpochWindowSec == 0 {
		cfg.EpochWindowSec = defaultEpochWindowSec
	}
	if cfg.EpochAcceptanceWindow == 0 {
		cfg.EpochAcceptanceWindow = defaultEpochAcceptanceWindow
	}
	if cfg.DifficultyCacheTTL <= 0 {
		cfg.DifficultyCacheTTL = defaultDifficultyCacheTTL
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultSubmitTimeout
	}
	if cfg.PoWCheckInterval <= 0 {
		cfg.PoWCheckInterval = defaultPoWCheckInterval
	}
	if cfg.PoWMaxIterations == 0 {
		cfg.PoWMaxIterations = defaultPoWMaxIterations
	}

	client := cfg.Client
	if client == nil {
		// Negative Timeout disables the client-level cap; pass 0
		// for the same effect at the http.Client level.
		t := cfg.Timeout
		if t < 0 {
			t = 0
		}
		client = DefaultClient(t)
	}

	return &HTTPSubmitter{
		cfg:         cfg,
		client:      client,
		operatorPub: pub,
	}, nil
}

// modeIsAuthenticated reports whether this submitter operates in
// Mode A (Bearer-token authenticated) vs Mode B (PoW stamp).
// Centralizes the dispatch decision so build/submit/batch paths
// agree without re-checking cfg.AuthToken.
func (s *HTTPSubmitter) modeIsAuthenticated() bool {
	return s.cfg.AuthToken != ""
}
