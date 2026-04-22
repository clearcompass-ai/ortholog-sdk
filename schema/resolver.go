package schema

import (
	"sync"
	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

const DefaultDeltaWindowSize = 10

type CachingResolver struct {
	mu    sync.RWMutex
	cache map[types.LogPosition]*builder.SchemaResolution
}

func NewCachingResolver() *CachingResolver {
	return &CachingResolver{cache: make(map[types.LogPosition]*builder.SchemaResolution)}
}

func (r *CachingResolver) Resolve(ref types.LogPosition, fetcher types.EntryFetcher) (*builder.SchemaResolution, error) {
	r.mu.RLock(); cached, ok := r.cache[ref]; r.mu.RUnlock()
	if ok { return cached, nil }
	meta, err := fetcher.Fetch(ref)
	if err != nil { return nil, err }
	if meta == nil {
		res := &builder.SchemaResolution{IsCommutative: false, DeltaWindowSize: DefaultDeltaWindowSize}
		r.cacheResult(ref, res); return res, nil
	}
	entry, err := envelope.Deserialize(meta.CanonicalBytes)
	if err != nil { return nil, err }
	res := &builder.SchemaResolution{
		IsCommutative: len(entry.Header.CommutativeOperations) > 0,
		DeltaWindowSize: DefaultDeltaWindowSize,
	}
	r.cacheResult(ref, res); return res, nil
}

func (r *CachingResolver) cacheResult(ref types.LogPosition, res *builder.SchemaResolution) {
	r.mu.Lock(); r.cache[ref] = res; r.mu.Unlock()
}
