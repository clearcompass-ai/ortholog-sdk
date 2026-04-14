package builder

import (
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

type EntryFetcher interface {
	Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error)
}

type SchemaResolver interface {
	Resolve(ref types.LogPosition, fetcher EntryFetcher) (*SchemaResolution, error)
}

type SchemaResolution struct {
	IsCommutative   bool
	DeltaWindowSize int
}

type PathResult uint8

const (
	PathResultCommentary PathResult = iota
	PathResultNewLeaf
	PathResultPathA
	PathResultPathB
	PathResultPathC
	PathResultPathD
	PathResultRejected
)

type BatchResult struct {
	NewRoot          [32]byte
	Mutations        []types.LeafMutation
	PathACounts      int
	PathBCounts      int
	PathCCounts      int
	PathDCounts      int
	CommentaryCounts int
	NewLeafCounts    int
	RejectedCounts   int
	UpdatedBuffer    *DeltaWindowBuffer
}

func ProcessBatch(
	tree *smt.Tree,
	entries []*envelope.Entry,
	positions []types.LogPosition,
	fetcher EntryFetcher,
	schemaRes SchemaResolver,
	localLogDID string,
	deltaBuffer *DeltaWindowBuffer,
) (*BatchResult, error) {
	if deltaBuffer == nil { deltaBuffer = NewDeltaWindowBuffer(10) }
	tree.StartTracking()
	result := &BatchResult{}
	for i, entry := range entries {
		pos := positions[i]
		pathResult, err := processEntry(tree, entry, pos, fetcher, schemaRes, localLogDID, deltaBuffer)
		if err != nil { pathResult = PathResultPathD }
		switch pathResult {
		case PathResultCommentary: result.CommentaryCounts++
		case PathResultNewLeaf: result.NewLeafCounts++
		case PathResultPathA: result.PathACounts++
		case PathResultPathB: result.PathBCounts++
		case PathResultPathC: result.PathCCounts++
		case PathResultPathD: result.PathDCounts++
		case PathResultRejected: result.RejectedCounts++
		}
	}
	mutations := tree.StopTracking()
	result.Mutations = mutations
	root, err := tree.Root()
	if err != nil { return nil, err }
	result.NewRoot = root
	result.UpdatedBuffer = deltaBuffer
	return result, nil
}
