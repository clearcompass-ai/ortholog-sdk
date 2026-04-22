package schema

import (
	"sync"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// DefaultDeltaWindowSize is the SDK's protocol-reference Δ-window
// depth for commutative OCC schemas (SDK-D7).
const DefaultDeltaWindowSize = 10

// CachingResolver memoises per-schema resolutions derived from the
// schema entry's Domain Payload. Thread-safe for concurrent Resolve
// calls — a single-flight-style race is harmless because Resolve is
// deterministic for a given schema entry.
//
// v7.5 rewires IsCommutative resolution to go through
// JSONParameterExtractor: CommutativeOperations lives in the schema's
// Domain Payload, not ControlHeader (Decision 52 layering restoration).
type CachingResolver struct {
	mu        sync.RWMutex
	cache     map[types.LogPosition]*types.SchemaResolution
	extractor *JSONParameterExtractor
}

// NewCachingResolver constructs a CachingResolver backed by the
// default JSONParameterExtractor.
func NewCachingResolver() *CachingResolver {
	return &CachingResolver{
		cache:     make(map[types.LogPosition]*types.SchemaResolution),
		extractor: NewJSONParameterExtractor(),
	}
}

// Resolve returns the schema resolution for a schema entry at `ref`.
// Missing schemas (fetcher returns nil) resolve to strict OCC — a
// safe default that lets pre-schema Path C entries continue under
// the conservative mode.
func (r *CachingResolver) Resolve(ref types.LogPosition, fetcher types.EntryFetcher) (*types.SchemaResolution, error) {
	r.mu.RLock()
	cached, ok := r.cache[ref]
	r.mu.RUnlock()
	if ok {
		return cached, nil
	}

	meta, err := fetcher.Fetch(ref)
	if err != nil {
		return nil, err
	}
	if meta == nil {
		res := &types.SchemaResolution{IsCommutative: false, DeltaWindowSize: DefaultDeltaWindowSize}
		r.cacheResult(ref, res)
		return res, nil
	}

	entry, err := envelope.Deserialize(meta.CanonicalBytes)
	if err != nil {
		return nil, err
	}

	// v7.5 Decision 52: CommutativeOperations lives in the schema
	// entry's Domain Payload, not ControlHeader. Route the read
	// through JSONParameterExtractor so the resolver and every
	// other Domain Payload consumer share one parser.
	//
	// A malformed payload (non-JSON, missing keys the extractor
	// rejects) degrades to strict OCC — same conservative default
	// as a missing schema. The extractor's error is not propagated:
	// a corrupted schema entry should not break every downstream
	// Path C classification, and strict OCC is the safe failure
	// mode (Decision 37).
	isCommutative := false
	if params, extErr := r.extractor.Extract(entry); extErr == nil && params != nil {
		isCommutative = len(params.CommutativeOperations) > 0
	}

	res := &types.SchemaResolution{
		IsCommutative:   isCommutative,
		DeltaWindowSize: DefaultDeltaWindowSize,
	}
	r.cacheResult(ref, res)
	return res, nil
}

func (r *CachingResolver) cacheResult(ref types.LogPosition, res *types.SchemaResolution) {
	r.mu.Lock()
	r.cache[ref] = res
	r.mu.Unlock()
}
