/*
FILE PATH:
    exchange/auth/nonce_store.go

DESCRIPTION:
    NonceStore defines the contract for the single-use-nonce mechanism
    used to prevent replay of signed requests that do NOT become log
    entries.

SCOPE — WHAT NONCE STORE IS FOR:
    Use NonceStore for endpoints whose signed request:
      (a) returns data with restricted access (private / gated content,
          where disclosure must be authorized per request)
      (b) triggers a side effect outside the log (outbound notification,
          external delivery, webhook firing, third-party call)
      (c) manipulates control-plane state (key rotation, operator
          configuration, endpoint registration, access-list changes)

SCOPE — WHAT NONCE STORE IS NOT FOR:
    Do NOT use NonceStore for log-entry submissions. Those are protected
    by a different mechanism:
      - The entry's canonical hash commits to a destination exchange
        (destination binding via Entry.Destination), preventing cross-
        exchange replay.
      - The log's canonical-hash uniqueness invariant dedups same-
        exchange replays of already-ingested entries.
      - The ingestion freshness window (exchange/policy/freshness.go)
        rejects stale entries being replayed into the log for the first
        time.
    Together these eliminate the replay surface for log-entry traffic
    without requiring forever-growing nonce storage.

CONTRACT — STRICT FOREVER:
    Reservations are PERMANENT. A nonce reserved today is still reserved
    decades later. Implementations MUST NOT garbage-collect or expire
    reservations. TTL, if present in the underlying storage layer (Redis
    TTL, Postgres partition rotation), is permitted ONLY for index-
    pruning / partition management; the semantic fact "this nonce was
    reserved" must survive forever. A forensic query years later must
    return the original reservation record.

CONTRACT — NAMESPACING:
    A single NonceStore instance belongs to a single exchange identity.
    If the underlying storage is shared across exchanges (one Redis
    cluster serving multiple exchanges in a federation), the
    IMPLEMENTATION MUST namespace keys by exchange DID to prevent
    cross-tenant collision or denial:

        key = "ortholog:" || exchange_did || ":" || nonce

    A malicious exchange reserving a nonce in a shared store must not
    be able to cause a healthy exchange's reservation to fail. The
    namespacing happens in the implementation, not in the caller.

CONTRACT — CONCURRENCY:
    Reserve MUST be safe for concurrent callers. Two goroutines calling
    Reserve with the same nonce result in exactly one success and one
    ErrNonceReserved — never two successes, never two errors of a
    different kind. Implementations may use whatever primitive they
    prefer (mutex, Redis SET NX, Postgres unique constraint, distributed
    lock).

CONTRACT — IDEMPOTENCY:
    Reserve is idempotent on already-reserved nonces: repeated calls
    return ErrNonceReserved deterministically. This is NOT "the first
    call succeeds and the second fails" — it is "the first call either
    succeeds or fails based on prior state; every subsequent call with
    the same nonce returns ErrNonceReserved."

KNOWN ATTACK SURFACES:
    A) Memory exhaustion: unbounded nonce reservations.
       Mitigation: the SDK enforces MaxValidityWindow on VerifyRequest.
       An attacker cannot reserve nonces with unbounded validity windows
       because requests exceeding the window are rejected before Reserve
       is called. The store receives only validated requests. For long-
       term storage growth, Postgres and Redis at 10B entries scale with
       known techniques (partitioning, sharding). Plan capacity.
    B) Timing side-channel: Reserve returns faster for reserved nonces
       than new ones.
       Mitigation: nonces should be unpredictable randoms; observing
       "has this random been seen" leaks no useful information.
       Constant-time is over-engineering for this use case.
    C) Cross-tenant denial in shared storage: if multiple exchanges
       share one store, a compromised exchange can reserve nonces on
       behalf of a healthy exchange.
       Mitigation: namespace every key by exchange DID (see Namespacing
       contract above).

KEY DEPENDENCIES:
    None. Pure interface + error definitions.
*/
package auth

import (
	"context"
	"errors"
)

// -------------------------------------------------------------------------------------------------
// 1) Errors
// -------------------------------------------------------------------------------------------------

// ErrNonceReserved is the sentinel returned by Reserve when the nonce
// has already been reserved. This is the expected "replay detected"
// signal and must be distinguishable from infrastructure errors by
// callers.
var ErrNonceReserved = errors.New("exchange/auth: nonce already reserved")

// ErrNonceStoreUnavailable indicates an infrastructure-level failure
// (database connection lost, Redis timeout). Callers should typically
// fail-closed on this error — rejecting the request — rather than
// letting it succeed without replay protection.
var ErrNonceStoreUnavailable = errors.New("exchange/auth: nonce store unavailable")

// ErrNonceEmpty indicates the caller passed an empty nonce string.
// Every nonce must be at least one byte; an empty nonce is a
// programming error.
var ErrNonceEmpty = errors.New("exchange/auth: nonce must not be empty")

// -------------------------------------------------------------------------------------------------
// 2) Interface
// -------------------------------------------------------------------------------------------------

// NonceStore is the contract implementations MUST satisfy. See the file
// header for the full semantic contract (strict-forever, namespacing,
// concurrency, idempotency, attack surfaces).
type NonceStore interface {
	// Reserve records a nonce as seen. Returns nil on success (first
	// time this nonce is seen). Returns ErrNonceReserved if the nonce
	// has already been reserved. Returns ErrNonceStoreUnavailable on
	// infrastructure error.
	//
	// Implementations MUST NOT garbage-collect successful reservations.
	// A nonce reserved is reserved forever.
	Reserve(ctx context.Context, nonce string) error
}
