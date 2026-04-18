/*
FILE PATH:
    exchange/auth/nonce_memory.go

DESCRIPTION:
    InMemoryNonceStore is the reference NonceStore implementation for
    development, tests, and single-process deployments with no replay-
    forensics requirement.

    ==================================================================
    PRODUCTION USE — READ THIS BEFORE DEPLOYING.
    ==================================================================
    InMemoryNonceStore is NOT suitable for:
      - Multi-replica deployments (each replica has its own map; an
        attacker replays across replicas)
      - Deployments where nonce forensics must survive process restart
        (the map dies with the process)
      - Deployments with more than one exchange served by this process
        (no namespacing — use a wrapper that prepends exchange DID)

    For production deployments, implement NonceStore against:
      - Postgres with a unique constraint on (exchange_did, nonce) and
        INSERT ... ON CONFLICT DO NOTHING RETURNING
      - Redis with SET NX (NO TTL — reservations are forever)
      - Any other durable, strongly-consistent KV store

    The SDK does NOT ship Postgres/Redis adapters by design — the
    40-60 lines of adapter code is trivial to write against your
    existing stack, and shipping it here would add a dependency every
    consumer has to carry. See nonce_store.go for the interface
    contract your implementation must satisfy.

KEY ARCHITECTURAL DECISIONS:
  - Single sync.Mutex guards the map. Not sync.RWMutex: Reserve is
    always a write path (check-then-insert must be atomic).
  - No TTL, no cleanup, no eviction. Strict-forever per the contract.
  - No size limit: the SDK's caller is responsible for bounding growth
    via MaxValidityWindow enforcement at the verifier. A store that
    runs out of memory is a signal to migrate to Postgres or Redis.
  - The metadata we store per nonce is minimal (reservation time)
    because this impl is for dev/test. Production impls may store more
    (signer DID, request hash, source IP) for forensic purposes — that
    additional metadata is schema-local, not part of the NonceStore
    interface.

KEY DEPENDENCIES:
    Standard library only (sync, time).
*/
package auth

import (
	"context"
	"sync"
	"time"
)

// -------------------------------------------------------------------------------------------------
// 1) InMemoryNonceStore
// -------------------------------------------------------------------------------------------------

// InMemoryNonceStore is a process-local, strict-forever NonceStore.
// See file header for production limitations.
type InMemoryNonceStore struct {
	mu       sync.Mutex
	reserved map[string]time.Time // nonce → reservation time (UTC)
}

// NewInMemoryNonceStore returns a ready-to-use, empty store.
func NewInMemoryNonceStore() *InMemoryNonceStore {
	return &InMemoryNonceStore{
		reserved: make(map[string]time.Time),
	}
}

// -------------------------------------------------------------------------------------------------
// 2) Reserve — the only interface method
// -------------------------------------------------------------------------------------------------

// Reserve records a nonce as seen. Returns nil on first sight,
// ErrNonceReserved on every subsequent call with the same nonce,
// ErrNonceEmpty on empty input. ctx is accepted for interface conformance
// and future-proofing but not currently consulted (Reserve is in-memory
// and synchronous).
func (s *InMemoryNonceStore) Reserve(ctx context.Context, nonce string) error {
	if nonce == "" {
		return ErrNonceEmpty
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.reserved[nonce]; ok {
		return ErrNonceReserved
	}
	s.reserved[nonce] = time.Now().UTC()
	return nil
}

// -------------------------------------------------------------------------------------------------
// 3) Diagnostic helpers (NOT part of NonceStore interface)
// -------------------------------------------------------------------------------------------------
//
// These methods exist for tests and operational inspection. They are NOT
// part of the NonceStore interface and production impls need not provide
// equivalents. Callers depending on these methods are, by construction,
// tied to InMemoryNonceStore and must migrate if they move to a durable
// backend.

// Size returns the number of reserved nonces currently tracked.
// Diagnostic only — do not use for replay-protection logic.
func (s *InMemoryNonceStore) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reserved)
}

// IsReserved reports whether a given nonce has been reserved.
// Diagnostic only — do not use for replay-protection logic in callers
// (that is Reserve's job, and must be atomic with the reservation).
func (s *InMemoryNonceStore) IsReserved(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.reserved[nonce]
	return ok
}

// ReservedAt returns the time a nonce was reserved and whether it was
// reserved at all. Diagnostic / forensic helper.
func (s *InMemoryNonceStore) ReservedAt(nonce string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.reserved[nonce]
	return t, ok
}
