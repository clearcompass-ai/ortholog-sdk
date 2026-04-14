// Package schema provides schema resolution for the builder and parameter
// extraction interfaces for verifiers.
package schema

import (
	"sync"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// DefaultDeltaWindowSize is the default delta window when the schema doesn't specify one.
const DefaultDeltaWindowSize = 10

// CachingResolver implements SchemaResolver with a position-keyed cache.
// Schemas are immutable at their position (pinned resolution), so the cache
// never needs invalidation.
type CachingResolver struct {
	mu    sync.RWMutex
	cache map[types.LogPosition]*builder.SchemaResolution
}

// NewCachingResolver creates a schema resolver with caching.
func NewCachingResolver() *CachingResolver {
	return &CachingResolver{
		cache: make(map[types.LogPosition]*builder.SchemaResolution),
	}
}

// Resolve reads the schema at the exact Schema_Ref position (pinned — no Origin_Tip
// following). The entry gets the schema version it references, not the latest version.
// New schema versions are new root entities with new log positions.
//
// Null Schema_Ref: callers should skip calling Resolve and default to non-commutative strict OCC.
// Binary decision per schema, not per entry (SDK-D7, Decision 25).
func (r *CachingResolver) Resolve(ref types.LogPosition, fetcher builder.EntryFetcher) (*builder.SchemaResolution, error) {
	// Check cache first (schemas are immutable at their position).
	r.mu.RLock()
	cached, ok := r.cache[ref]
	r.mu.RUnlock()
	if ok {
		return cached, nil
	}

	// Fetch the schema entry at the exact position (PINNED).
	meta, err := fetcher.Fetch(ref)
	if err != nil {
		return nil, err
	}
	if meta == nil {
		// Schema entry not found. Default to non-commutative.
		res := &builder.SchemaResolution{
			IsCommutative:   false,
			DeltaWindowSize: DefaultDeltaWindowSize,
		}
		r.cacheResult(ref, res)
		return res, nil
	}

	entry, err := envelope.Deserialize(meta.CanonicalBytes)
	if err != nil {
		return nil, err
	}

	// SDK-D7: Commutative_Operations is a boolean check.
	// Non-empty = delta-window CRDT. Empty/null = strict OCC.
	res := &builder.SchemaResolution{
		IsCommutative:   len(entry.Header.CommutativeOperations) > 0,
		DeltaWindowSize: DefaultDeltaWindowSize,
	}

	r.cacheResult(ref, res)
	return res, nil
}

func (r *CachingResolver) cacheResult(ref types.LogPosition, res *builder.SchemaResolution) {
	r.mu.Lock()
	r.cache[ref] = res
	r.mu.Unlock()
}
