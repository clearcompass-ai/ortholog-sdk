package auth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// ─────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────

// newTestRedis stands up an in-process miniredis and returns a
// connected client. Cleanup auto-registers via t.Cleanup.
func newTestRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return client, mr
}

func newTestStore(t *testing.T, did string) (*RedisNonceStore, *miniredis.Miniredis) {
	t.Helper()
	client, mr := newTestRedis(t)
	s, err := NewRedisNonceStore(RedisNonceStoreConfig{
		Client:      client,
		ExchangeDID: did,
	})
	if err != nil {
		t.Fatalf("NewRedisNonceStore: %v", err)
	}
	return s, mr
}

// ─────────────────────────────────────────────────────────────────────
// Constructor
// ─────────────────────────────────────────────────────────────────────

func TestNewRedisNonceStore_NilClient(t *testing.T) {
	_, err := NewRedisNonceStore(RedisNonceStoreConfig{ExchangeDID: "did:key:zX"})
	if !errors.Is(err, ErrInvalidRedisConfig) {
		t.Fatalf("got %v, want ErrInvalidRedisConfig", err)
	}
}

func TestNewRedisNonceStore_EmptyExchangeDID(t *testing.T) {
	client, _ := newTestRedis(t)
	_, err := NewRedisNonceStore(RedisNonceStoreConfig{Client: client})
	if !errors.Is(err, ErrInvalidRedisConfig) {
		t.Fatalf("got %v, want ErrInvalidRedisConfig", err)
	}
}

func TestNewRedisNonceStore_DefaultKeyPrefix(t *testing.T) {
	s, _ := newTestStore(t, "did:key:zX")
	if s.keyPrefix != DefaultRedisKeyPrefix {
		t.Errorf("keyPrefix=%q, want %q", s.keyPrefix, DefaultRedisKeyPrefix)
	}
}

func TestNewRedisNonceStore_CustomKeyPrefix(t *testing.T) {
	client, _ := newTestRedis(t)
	s, err := NewRedisNonceStore(RedisNonceStoreConfig{
		Client: client, ExchangeDID: "did:key:zX", KeyPrefix: "custom:",
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if s.keyPrefix != "custom:" {
		t.Errorf("keyPrefix=%q", s.keyPrefix)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Reserve happy/replay paths
// ─────────────────────────────────────────────────────────────────────

func TestReserve_FirstCallSucceeds(t *testing.T) {
	s, _ := newTestStore(t, "did:key:zX")
	if err := s.Reserve(context.Background(), "n1"); err != nil {
		t.Fatalf("first call: %v", err)
	}
}

func TestReserve_SecondCallReplay(t *testing.T) {
	s, _ := newTestStore(t, "did:key:zX")
	if err := s.Reserve(context.Background(), "n1"); err != nil {
		t.Fatalf("first: %v", err)
	}
	err := s.Reserve(context.Background(), "n1")
	if !errors.Is(err, ErrNonceReserved) {
		t.Fatalf("got %v, want ErrNonceReserved", err)
	}
}

func TestReserve_EmptyNonce(t *testing.T) {
	s, _ := newTestStore(t, "did:key:zX")
	if err := s.Reserve(context.Background(), ""); !errors.Is(err, ErrNonceEmpty) {
		t.Fatalf("got %v, want ErrNonceEmpty", err)
	}
}

func TestReserve_RedisError(t *testing.T) {
	client, mr := newTestRedis(t)
	s, _ := NewRedisNonceStore(RedisNonceStoreConfig{
		Client: client, ExchangeDID: "did:key:zX",
	})
	mr.Close() // tear down the server; subsequent calls fail
	err := s.Reserve(context.Background(), "n1")
	if !errors.Is(err, ErrNonceStoreUnavailable) {
		t.Fatalf("got %v, want ErrNonceStoreUnavailable", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Strict-forever — no TTL
// ─────────────────────────────────────────────────────────────────────

func TestReserve_NoTTL(t *testing.T) {
	s, mr := newTestStore(t, "did:key:zX")
	if err := s.Reserve(context.Background(), "perpetual"); err != nil {
		t.Fatalf("%v", err)
	}
	key := s.keyFor("perpetual")
	if !mr.Exists(key) {
		t.Fatal("key not stored")
	}
	// miniredis.TTL returns 0 for keys with no TTL set. SET NX
	// without EX MUST land here.
	if ttl := mr.TTL(key); ttl != 0 {
		t.Errorf("key has TTL=%v, want 0 (strict-forever)", ttl)
	}
}

// ─────────────────────────────────────────────────────────────────────
// DID namespacing — cross-tenant safety
// ─────────────────────────────────────────────────────────────────────

func TestReserve_DIDNamespacing(t *testing.T) {
	client, _ := newTestRedis(t)
	storeA, err := NewRedisNonceStore(RedisNonceStoreConfig{
		Client: client, ExchangeDID: "did:key:zA",
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	storeB, err := NewRedisNonceStore(RedisNonceStoreConfig{
		Client: client, ExchangeDID: "did:key:zB",
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	// Same nonce string must succeed on both stores.
	if err := storeA.Reserve(context.Background(), "shared"); err != nil {
		t.Fatalf("A.Reserve: %v", err)
	}
	if err := storeB.Reserve(context.Background(), "shared"); err != nil {
		t.Fatalf("B.Reserve: %v (DID namespacing broken)", err)
	}
	// Replay on A must still fail.
	if err := storeA.Reserve(context.Background(), "shared"); !errors.Is(err, ErrNonceReserved) {
		t.Fatalf("A replay: %v", err)
	}
}

func TestReserve_MaliciousTenantCannotDoSHealthy(t *testing.T) {
	client, _ := newTestRedis(t)
	healthy, _ := NewRedisNonceStore(RedisNonceStoreConfig{
		Client: client, ExchangeDID: "did:key:zHealthy",
	})
	malicious, _ := NewRedisNonceStore(RedisNonceStoreConfig{
		Client: client, ExchangeDID: "did:key:zEvil",
	})
	// Malicious tenant reserves a million nonces (we only do 100).
	for i := 0; i < 100; i++ {
		if err := malicious.Reserve(context.Background(),
			"evil-"+strInt(i)); err != nil {
			t.Fatalf("malicious.Reserve: %v", err)
		}
	}
	// Healthy tenant uses one of those exact same nonce strings.
	// MUST succeed because the namespace differs.
	if err := healthy.Reserve(context.Background(), "evil-50"); err != nil {
		t.Fatalf("healthy reservation collided with malicious: %v", err)
	}
}

// strInt formats an int as a decimal string without pulling in
// strconv just for the test fixture.
func strInt(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ─────────────────────────────────────────────────────────────────────
// Concurrency — atomic claim
// ─────────────────────────────────────────────────────────────────────

func TestReserve_ConcurrentRaceExactlyOneSuccess(t *testing.T) {
	s, _ := newTestStore(t, "did:key:zX")
	const N = 100
	var wg sync.WaitGroup
	var successes atomic.Int32
	var replays atomic.Int32
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			err := s.Reserve(context.Background(), "raced")
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrNonceReserved):
				replays.Add(1)
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Errorf("successes=%d, want exactly 1", successes.Load())
	}
	if replays.Load() != N-1 {
		t.Errorf("replays=%d, want %d", replays.Load(), N-1)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Compile-time pin
// ─────────────────────────────────────────────────────────────────────

func TestRedisNonceStore_SatisfiesInterface(t *testing.T) {
	var _ NonceStore = (*RedisNonceStore)(nil)
}

// ─────────────────────────────────────────────────────────────────────
// Time import smoke (for ctx with deadlines in future tests)
// ─────────────────────────────────────────────────────────────────────

func TestReserve_HonorsCtxDeadline(t *testing.T) {
	s, _ := newTestStore(t, "did:key:zX")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Reserve(ctx, "n-with-deadline"); err != nil {
		t.Fatalf("%v", err)
	}
}
