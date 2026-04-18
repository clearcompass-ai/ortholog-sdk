/*
FILE PATH:
    exchange/auth/signed_request.go

DESCRIPTION:
    Signed-request envelope and verification for exchange-relay API
    authentication. Entities authenticate HTTP requests to the exchange by
    signing a structured request envelope with the DID-controlled key.
    Separate from — and MUST NOT be confused with — the entry signature
    that commits to the canonical entry hash inside the Ortholog log.

KEY ARCHITECTURAL DECISIONS:
    - This package handles SESSION / API AUTH, not entry signing. The two
      signature surfaces are kept deliberately separate:
          * Entry signature       -> signs canonical entry hash, committed
                                     to the log, reconstructible decades later
          * Signed request (here) -> signs an API request envelope, ephemeral,
                                     bound to domain and expiry, used for
                                     authenticating exchange calls
      The exchange does not issue long-lived tokens. Every request carries
      its own fresh signature.
    - Envelope is canonicalized before signing/verifying. We define a fixed
      byte layout (not JSON) to eliminate canonicalization ambiguity. JSON
      cannot be safely canonicalized across clients — the byte layout can.
    - Mandatory fields enforce replay protection on multiple axes:
          domain    prevents cross-service replay
          chainID   prevents cross-chain replay (for eip155 DIDs)
          nonce     prevents replay within the domain
          issuedAt  + expiresAt bound the validity window
      Any missing or malformed field fails the verify.
    - Validity windows are tempo-scoped (Automated / Interactive /
      Deliberative) so callers pick a window matching the signing
      tempo of the endpoint, not a role or domain-specific label. The
      SDK enforces a hard MaxValidityWindow ceiling above which any
      envelope is rejected unconditionally.
    - Nonce freshness is delegated to an injected NonceStore with
      strict-forever semantics (see exchange/auth/nonce_store.go). The
      store is required UNLESS the caller explicitly opts into
      no-replay-check via VerifyRequestOptions.AllowNoReplayCheck — a
      conscious decision the caller must make, never a silent default.
    - Clock skew tolerance is configurable but defaults to MaxClockSkew
      (30s) on each side of the validity window. Outside that window,
      verification fails loudly.

OVERVIEW:
    Canonical envelope byte layout (all fields length-prefixed):
        u8      version (=1)
        len+bytes did
        len+bytes domain
        len+bytes chain_id    (ASCII, "" for non-EVM)
        len+bytes nonce
        u64     issued_at_unix_seconds
        u64     expires_at_unix_seconds
        len+bytes method      (HTTP verb, uppercased)
        len+bytes path        (absolute path, no query)
        32 bytes body_sha256  (all zeros for no body)

    The canonical hash is sha256(canonical_envelope_bytes). That 32-byte
    hash is what the DID-controlled key signs.

    Verify:
        1. Parse envelope
        2. Check version, required fields
        3. Check expiry vs now (with skew tolerance)
        4. Check validity window <= opts.ValidityWindow and MaxValidityWindow
        5. Reserve the nonce in NonceStore (fails if reused)
           — skipped only if opts.AllowNoReplayCheck is true
        6. Compute canonical hash
        7. Call registry.Verify(did, hash, sig, algoID)

KEY DEPENDENCIES:
    - did/verifier_registry.go: VerifierRegistry for the actual signature check
    - crypto/sha256 (stdlib):   canonical hash
    - exchange/auth/nonce_store.go: NonceStore interface
*/
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// -------------------------------------------------------------------------------------------------
// 1) Constants
// -------------------------------------------------------------------------------------------------

// EnvelopeVersion is the current signed-request envelope version. Incrementing
// this is a wire-breaking change across the ecosystem.
const EnvelopeVersion uint8 = 1

// Validity windows are tempo-scoped. Callers pick a window matching the
// signing tempo of the endpoint. The SDK is domain-agnostic; consumers
// map their own signer categories onto these tempos. Illustrative mappings:
//
//   Automated   → service daemons, scheduled jobs, protocol actors
//                 (witnesses, anchor publishers, cross-log mirrors)
//   Interactive → humans at a UI executing routine input
//   Deliberative → humans exercising judgment in review-and-decide flows
const (
	// ValidityAutomated is for machine-to-machine signed requests where
	// no human is in the loop. Replays must be detected within seconds.
	ValidityAutomated = 60 * time.Second

	// ValidityInteractive is for humans at a UI executing routine input.
	// Accommodates UI latency and immediate human response.
	ValidityInteractive = 5 * time.Minute

	// ValidityDeliberative is for humans in a review-and-decide workflow.
	// Accommodates a pause for consideration between opening a signing
	// interface and committing.
	ValidityDeliberative = 30 * time.Minute
)

// MaxValidityWindow is the hard ceiling the SDK will accept. Envelopes
// whose ExpiresAt-IssuedAt span exceeds this are rejected unconditionally,
// regardless of caller-level policy. Longer windows indicate either a
// misconfiguration or a design that needs revisiting; pre-signed durable
// actions should use a different mechanism.
const MaxValidityWindow = 1 * time.Hour

// MaxClockSkew is the tolerance applied to IssuedAt/ExpiresAt comparison
// to account for client/server clock drift. Asymmetric on both sides of
// the validity window.
const MaxClockSkew = 30 * time.Second

// DefaultClockSkew is retained for callers that read it directly. New
// code should prefer MaxClockSkew (same value, clearer name).
const DefaultClockSkew = MaxClockSkew

// ZeroBodyHash is the canonical body-hash value for requests with no body.
// A signer must use this value explicitly; the empty-string body hash differs
// from "no body present", preventing ambiguity.
var ZeroBodyHash [32]byte

// -------------------------------------------------------------------------------------------------
// 2) Errors
// -------------------------------------------------------------------------------------------------

var (
	ErrEnvelopeMalformed       = errors.New("exchange/auth: envelope malformed")
	ErrEnvelopeExpired         = errors.New("exchange/auth: envelope expired")
	ErrEnvelopeNotYetValid     = errors.New("exchange/auth: envelope not yet valid")
	ErrEnvelopeValidityTooWide = errors.New("exchange/auth: envelope validity window exceeds MaxValidityWindow")
	ErrEnvelopeValidityTooWideForEndpoint = errors.New("exchange/auth: envelope validity window exceeds VerifyRequestOptions.ValidityWindow")
	ErrEnvelopeDomainMismatch  = errors.New("exchange/auth: envelope domain does not match expected")
	ErrEnvelopeNonceReused     = errors.New("exchange/auth: envelope nonce reused")
	ErrEnvelopeFieldMissing    = errors.New("exchange/auth: envelope required field missing")
	ErrNonceStoreRequired      = errors.New("exchange/auth: NonceStore required (or set VerifyRequestOptions.AllowNoReplayCheck=true)")
)

// -------------------------------------------------------------------------------------------------
// 3) Envelope
// -------------------------------------------------------------------------------------------------

// SignedRequestEnvelope is the structured payload that an entity signs to
// authenticate an API request to the exchange.
type SignedRequestEnvelope struct {
	// Version of the envelope format. MUST equal EnvelopeVersion.
	Version uint8

	// DID identifies the signer. Any DID method recognized by the verifier
	// registry is acceptable.
	DID string

	// Domain is the audience — the exchange endpoint hostname the request
	// is intended for. Prevents cross-service replay.
	Domain string

	// ChainID is the CAIP-2 chain reference for EVM DIDs, e.g. "1" for
	// mainnet. Empty string for non-EVM DIDs. Prevents cross-chain replay.
	ChainID string

	// Nonce is a unique string scoped to (DID, Domain). Used by the server
	// to reject replay. Clients SHOULD use a UUID or similar.
	Nonce string

	// IssuedAt is the envelope creation time. Rejected if too far in the
	// future relative to server clock.
	IssuedAt time.Time

	// ExpiresAt is the envelope expiry. Rejected if in the past.
	ExpiresAt time.Time

	// Method is the HTTP method of the request (uppercased).
	Method string

	// Path is the absolute path of the request, without query string.
	Path string

	// BodyHash is sha256 of the request body, or ZeroBodyHash for no body.
	BodyHash [32]byte
}

// -------------------------------------------------------------------------------------------------
// 4) Canonicalization
// -------------------------------------------------------------------------------------------------

// Canonicalize produces the canonical byte encoding of the envelope. The
// sha256 of these bytes is what the signer signs.
func (e *SignedRequestEnvelope) Canonicalize() ([]byte, error) {
	if err := e.validateFields(); err != nil {
		return nil, err
	}

	out := make([]byte, 0, 256)
	out = append(out, e.Version)
	out = appendLengthPrefixed(out, []byte(e.DID))
	out = appendLengthPrefixed(out, []byte(e.Domain))
	out = appendLengthPrefixed(out, []byte(e.ChainID))
	out = appendLengthPrefixed(out, []byte(e.Nonce))
	out = appendUint64(out, uint64(e.IssuedAt.Unix()))
	out = appendUint64(out, uint64(e.ExpiresAt.Unix()))
	out = appendLengthPrefixed(out, []byte(e.Method))
	out = appendLengthPrefixed(out, []byte(e.Path))
	out = append(out, e.BodyHash[:]...)
	return out, nil
}

// CanonicalHash returns sha256(canonical bytes). This is the 32-byte value
// that the DID-controlled key signs.
func (e *SignedRequestEnvelope) CanonicalHash() ([32]byte, error) {
	canonical, err := e.Canonicalize()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

// validateFields enforces required non-empty fields and field-shape rules,
// plus the SDK-level MaxValidityWindow ceiling. Endpoint-level narrower
// windows (opts.ValidityWindow) are checked by VerifyRequest.
func (e *SignedRequestEnvelope) validateFields() error {
	if e.Version != EnvelopeVersion {
		return fmt.Errorf("%w: version %d, expected %d",
			ErrEnvelopeMalformed, e.Version, EnvelopeVersion)
	}
	if e.DID == "" {
		return fmt.Errorf("%w: DID", ErrEnvelopeFieldMissing)
	}
	if e.Domain == "" {
		return fmt.Errorf("%w: Domain", ErrEnvelopeFieldMissing)
	}
	if e.Nonce == "" {
		return fmt.Errorf("%w: Nonce", ErrEnvelopeFieldMissing)
	}
	if e.Method == "" {
		return fmt.Errorf("%w: Method", ErrEnvelopeFieldMissing)
	}
	if e.Method != strings.ToUpper(e.Method) {
		return fmt.Errorf("%w: Method must be uppercase, got %q",
			ErrEnvelopeMalformed, e.Method)
	}
	if e.Path == "" {
		return fmt.Errorf("%w: Path", ErrEnvelopeFieldMissing)
	}
	if !strings.HasPrefix(e.Path, "/") {
		return fmt.Errorf("%w: Path must start with '/', got %q",
			ErrEnvelopeMalformed, e.Path)
	}
	if strings.ContainsRune(e.Path, '?') {
		return fmt.Errorf("%w: Path must not contain query string",
			ErrEnvelopeMalformed)
	}
	if e.IssuedAt.IsZero() || e.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: IssuedAt and ExpiresAt required",
			ErrEnvelopeFieldMissing)
	}
	if !e.ExpiresAt.After(e.IssuedAt) {
		return fmt.Errorf("%w: ExpiresAt must be after IssuedAt",
			ErrEnvelopeMalformed)
	}
	if e.ExpiresAt.Sub(e.IssuedAt) > MaxValidityWindow {
		return fmt.Errorf("%w: %s",
			ErrEnvelopeValidityTooWide,
			e.ExpiresAt.Sub(e.IssuedAt))
	}
	return nil
}

// appendLengthPrefixed appends a 4-byte big-endian length followed by the
// data bytes. The length is u32 — fields longer than 4 GiB are not supported
// and would fail the length cast (envelopes should never approach this).
func appendLengthPrefixed(dst []byte, data []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	dst = append(dst, lenBuf[:]...)
	dst = append(dst, data...)
	return dst
}

// appendUint64 appends a big-endian u64 to dst.
func appendUint64(dst []byte, v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return append(dst, buf[:]...)
}

// -------------------------------------------------------------------------------------------------
// 5) VerifyRequest
// -------------------------------------------------------------------------------------------------

// VerifyRequestOptions configures VerifyRequest behavior.
type VerifyRequestOptions struct {
	// ExpectedDomain is the exchange's expected audience. If non-empty,
	// envelopes whose Domain does not equal this value are rejected.
	ExpectedDomain string

	// ClockSkew is the tolerance applied on both sides of the validity
	// window. Defaults to MaxClockSkew if zero.
	ClockSkew time.Duration

	// ValidityWindow is the maximum (ExpiresAt - IssuedAt) the caller
	// accepts for this endpoint. If zero, defaults to MaxValidityWindow
	// (no caller-side tightening). Values greater than MaxValidityWindow
	// are rejected — the SDK hard ceiling always wins.
	//
	// Callers typically set this to one of the ValidityAutomated /
	// ValidityInteractive / ValidityDeliberative constants based on the
	// signing tempo of the endpoint.
	ValidityWindow time.Duration

	// AllowNoReplayCheck permits VerifyRequest to be called with a nil
	// NonceStore. MUST be set deliberately — a nil store with
	// AllowNoReplayCheck=false returns ErrNonceStoreRequired.
	//
	// Legitimate cases for setting this to true:
	//   - The endpoint's signed request becomes a log entry; the log's
	//     canonical-hash dedup + destination binding + freshness window
	//     already provide replay protection.
	//   - A test harness exercising verification without replay concerns.
	//
	// Never set this on endpoints that return private data, trigger side
	// effects, or manipulate control-plane state without a backing
	// NonceStore.
	AllowNoReplayCheck bool

	// Now returns the current time. Defaults to time.Now if nil.
	// Exposed for testing.
	Now func() time.Time
}

// VerifyRequest verifies a signed request envelope end-to-end.
//
// Steps:
//  1. Validate envelope structure and field shape (includes SDK MaxValidityWindow).
//  2. Check validity window against opts.ValidityWindow if set.
//  3. Check Now() vs IssuedAt/ExpiresAt with ClockSkew tolerance.
//  4. Check Domain matches ExpectedDomain (if set).
//  5. Reserve the nonce in NonceStore (fails if reused) — skipped if
//     nonces==nil AND opts.AllowNoReplayCheck==true.
//  6. Compute canonical hash.
//  7. Call registry.Verify(did, hash, sig, algoID).
//
// Any step failing fails the whole verification.
func VerifyRequest(
	registry *did.VerifierRegistry,
	env *SignedRequestEnvelope,
	sig []byte,
	algoID uint16,
	nonces NonceStore,
	opts VerifyRequestOptions,
) error {
	if registry == nil {
		return fmt.Errorf("exchange/auth: VerifierRegistry required")
	}
	if env == nil {
		return fmt.Errorf("exchange/auth: envelope required")
	}

	// NonceStore discipline: require a store unless the caller has
	// explicitly opted out of replay protection.
	if nonces == nil && !opts.AllowNoReplayCheck {
		return ErrNonceStoreRequired
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	skew := opts.ClockSkew
	if skew <= 0 {
		skew = MaxClockSkew
	}

	// Endpoint-level validity window: defaults to MaxValidityWindow. A
	// caller-specified value above MaxValidityWindow is clamped (the SDK
	// ceiling is authoritative), rejected by validateFields regardless.
	endpointWindow := opts.ValidityWindow
	if endpointWindow <= 0 {
		endpointWindow = MaxValidityWindow
	}
	if endpointWindow > MaxValidityWindow {
		endpointWindow = MaxValidityWindow
	}

	// Validate fields (also called by Canonicalize, but we want fast failure
	// before doing network / crypto work).
	if err := env.validateFields(); err != nil {
		return err
	}

	// Endpoint-level narrower window check (validateFields already enforced
	// the SDK-level MaxValidityWindow).
	if env.ExpiresAt.Sub(env.IssuedAt) > endpointWindow {
		return fmt.Errorf("%w: %s > %s",
			ErrEnvelopeValidityTooWideForEndpoint,
			env.ExpiresAt.Sub(env.IssuedAt),
			endpointWindow)
	}

	// Validity window vs. wall clock.
	t := now()
	if t.Before(env.IssuedAt.Add(-skew)) {
		return fmt.Errorf("%w: now=%s issuedAt=%s",
			ErrEnvelopeNotYetValid, t.Format(time.RFC3339), env.IssuedAt.Format(time.RFC3339))
	}
	if t.After(env.ExpiresAt.Add(skew)) {
		return fmt.Errorf("%w: now=%s expiresAt=%s",
			ErrEnvelopeExpired, t.Format(time.RFC3339), env.ExpiresAt.Format(time.RFC3339))
	}

	// Domain.
	if opts.ExpectedDomain != "" && env.Domain != opts.ExpectedDomain {
		return fmt.Errorf("%w: got %q, expected %q",
			ErrEnvelopeDomainMismatch, env.Domain, opts.ExpectedDomain)
	}

	// Nonce (reserve before signature verification — cheaper to fail fast
	// on a replay than to run ecrecover first). Skipped if the caller
	// opted out.
	if nonces != nil {
		if err := nonces.Reserve(context.Background(), env.Nonce); err != nil {
			return fmt.Errorf("%w: %v", ErrEnvelopeNonceReused, err)
		}
	}

	// Signature.
	hash, err := env.CanonicalHash()
	if err != nil {
		return err
	}
	return registry.Verify(env.DID, hash[:], sig, algoID)
}
