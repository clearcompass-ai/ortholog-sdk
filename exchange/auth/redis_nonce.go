/*
Package auth — redis_nonce.go provides a distributed NonceStore
backed by Redis. Production replacement for InMemoryNonceStore in
multi-replica deployments.

Why this matters:

	A single SDK consumer running N pods behind a load balancer
	with InMemoryNonceStore has N disjoint nonce maps. An attacker
	can replay one signed request to N different pods, bypassing
	replay protection N-1 times. RedisNonceStore solves this by
	moving the nonce map into shared, atomic, persistent storage.

Key shape:

	{KeyPrefix}{ExchangeDID}:{nonce}

	Default KeyPrefix is "ortholog:nonce:". The ExchangeDID
	namespacing prevents cross-tenant denial in shared Redis
	clusters (per nonce_store.go's CONTRACT — NAMESPACING).

Strict-forever:

	SET NX (no EX) — keys never expire. Operators who need to
	compact storage do so via Redis-level maintenance, not via
	per-key TTL. The semantic fact "this nonce was reserved" must
	survive forever.
*/
package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// ─────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────

// DefaultRedisKeyPrefix is the prefix every key receives unless
// overridden in the config. Includes the trailing colon so the
// shape is "{prefix}{exchange_did}:{nonce}" without ambiguity.
const DefaultRedisKeyPrefix = "ortholog:nonce:"

// RedisNonceStoreConfig configures RedisNonceStore.
type RedisNonceStoreConfig struct {
	// Client is the Redis client. Required. Accepts any
	// implementation of redis.UniversalClient: *redis.Client (single
	// node, miniredis), *redis.ClusterClient (cluster),
	// *redis.Ring (sharded), etc.
	Client redis.UniversalClient

	// ExchangeDID namespaces every key. Required to prevent
	// cross-tenant collision in shared Redis instances.
	ExchangeDID string

	// KeyPrefix overrides the default "ortholog:nonce:" prefix. The
	// final key shape is {KeyPrefix}{ExchangeDID}:{nonce}. Empty
	// uses DefaultRedisKeyPrefix.
	KeyPrefix string
}

// ─────────────────────────────────────────────────────────────────────
// Errors specific to RedisNonceStore
// ─────────────────────────────────────────────────────────────────────

// ErrInvalidRedisConfig wraps constructor validation failures.
var ErrInvalidRedisConfig = errors.New("exchange/auth: invalid RedisNonceStore configuration")

// ─────────────────────────────────────────────────────────────────────
// RedisNonceStore
// ─────────────────────────────────────────────────────────────────────

// RedisNonceStore is the distributed strict-forever NonceStore.
// Goroutine-safe (delegates to Redis client which is concurrent-safe).
type RedisNonceStore struct {
	client      redis.UniversalClient
	keyPrefix   string
	exchangeDID string
}

// NewRedisNonceStore validates cfg and returns a ready-to-use store.
// Constructor errors wrap ErrInvalidRedisConfig.
func NewRedisNonceStore(cfg RedisNonceStoreConfig) (*RedisNonceStore, error) {
	if cfg.Client == nil {
		return nil, fmt.Errorf("%w: Client required", ErrInvalidRedisConfig)
	}
	if cfg.ExchangeDID == "" {
		return nil, fmt.Errorf("%w: ExchangeDID required", ErrInvalidRedisConfig)
	}
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = DefaultRedisKeyPrefix
	}
	return &RedisNonceStore{
		client:      cfg.Client,
		keyPrefix:   prefix,
		exchangeDID: cfg.ExchangeDID,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// Reserve — the single NonceStore method
// ─────────────────────────────────────────────────────────────────────

// Reserve atomically marks a nonce as seen via Redis SET NX. Returns
// nil on first sight, ErrNonceReserved on second-and-subsequent
// sights, ErrNonceEmpty on empty input, ErrNonceStoreUnavailable on
// Redis errors.
//
// SET NX (no EX) makes reservations permanent. The single Redis
// SET command is atomic across the cluster, so two pods racing on
// the same (DID, nonce) result in exactly one success.
func (s *RedisNonceStore) Reserve(ctx context.Context, nonce string) error {
	if nonce == "" {
		return ErrNonceEmpty
	}
	key := s.keyFor(nonce)

	// SetNX with expiration=0 means no TTL — the key is permanent.
	// Returns true if the key was set (first reservation), false if
	// the key already existed (replay).
	ok, err := s.client.SetNX(ctx, key, reserveValue(), 0).Result()
	if err != nil {
		return fmt.Errorf("%w: SET NX: %v", ErrNonceStoreUnavailable, err)
	}
	if !ok {
		return ErrNonceReserved
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// keyFor builds the namespaced Redis key for a nonce. Format:
//
//	{prefix}{exchange_did}:{nonce}
//
// The colon between exchange_did and nonce is unambiguous because
// the prefix and exchange_did are caller-controlled (set at
// construction) and the nonce is the only variable component.
// Production deployments using DIDs containing colons (did:web:x)
// remain unambiguous because the trailing-colon-then-nonce pattern
// is fixed.
func (s *RedisNonceStore) keyFor(nonce string) string {
	return s.keyPrefix + s.exchangeDID + ":" + nonce
}

// reserveValue returns the value stored at each reserved key. The
// value itself is not consulted by Reserve (only the existence of
// the key matters), but Redis requires a non-empty value for SET.
// "1" is short and human-readable in redis-cli inspections; the
// reservation timestamp is the Redis-level OBJECT IDLETIME.
//
// Forensic-grade impls might store JSON-encoded {signer_did,
// reserved_at, request_hash} here — this trivial value is the
// minimum required for the strict-forever contract.
func reserveValue() string { return "1" }

// ─────────────────────────────────────────────────────────────────────
// Compile-time interface assertion
// ─────────────────────────────────────────────────────────────────────

// Pin: any drift in NonceStore breaks the build before tests run.
var _ NonceStore = (*RedisNonceStore)(nil)
