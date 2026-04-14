// Package builder implements the deterministic state resolution engine.
// Four paths. Local-only. The single most critical piece of code in the protocol.
package builder

import (
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// EntryFetcher retrieves entries from the local log.
// Contract: all returned entries have had signatures verified at admission (SDK-D5).
// The builder trusts this invariant and performs DID string comparisons, not
// signature verification.
type EntryFetcher interface {
	Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error)
}

// SchemaResolver resolves schema entries for commutative operation checks.
type SchemaResolver interface {
	// Resolve reads the schema at the exact Schema_Ref position (pinned, no Origin_Tip following)
	// and returns whether it declares commutative operations.
	Resolve(ref types.LogPosition, fetcher EntryFetcher) (*SchemaResolution, error)
}

// SchemaResolution is the builder-relevant result of schema resolution.
type SchemaResolution struct {
	IsCommutative   bool // Commutative_Operations non-empty (SDK-D7)
	DeltaWindowSize int  // From schema or default 10
}

// PathResult describes what the builder did with a single entry.
type PathResult uint8

const (
	PathResultCommentary  PathResult = iota // No leaf created or updated
	PathResultNewLeaf                        // New leaf created (root entity)
	PathResultPathA                          // Origin_Tip updated via same signer
	PathResultPathB                          // Origin_Tip updated via delegation
	PathResultPathC                          // Origin or Authority tip updated via scope
	PathResultPathD                          // No valid authority, SMT ignores
	PathResultRejected                       // Rejected (loop, depth, OCC mismatch)
)

// BatchResult is the output of ProcessBatch.
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

// ProcessBatch is the ONLY public entry point for the builder.
// No single-entry Process — batches only (pilot Exp 4).
//
// Input: SMT tree, entries in log sequence order, entry fetcher, schema resolver,
// local log DID, and delta-window authority history buffer.
// Output: new root, mutations, path counts, and updated buffer.
//
// The builder is local-only (Decision 47): all referenced LogPositions are checked
// for local log DID. Foreign positions fall through to Path D.
func ProcessBatch(
	tree *smt.Tree,
	entries []*envelope.Entry,
	positions []types.LogPosition, // Log position for each entry
	fetcher EntryFetcher,
	schemaRes SchemaResolver,
	localLogDID string,
	deltaBuffer *DeltaWindowBuffer,
) (*BatchResult, error) {
	if deltaBuffer == nil {
		deltaBuffer = NewDeltaWindowBuffer(10)
	}

	tree.StartTracking()

	result := &BatchResult{}

	for i, entry := range entries {
		pos := positions[i]
		pathResult, err := processEntry(tree, entry, pos, fetcher, schemaRes, localLogDID, deltaBuffer)
		if err != nil {
			// Processing errors are logged but don't abort the batch.
			// The entry falls through to Path D behavior.
			pathResult = PathResultPathD
		}

		switch pathResult {
		case PathResultCommentary:
			result.CommentaryCounts++
		case PathResultNewLeaf:
			result.NewLeafCounts++
		case PathResultPathA:
			result.PathACounts++
		case PathResultPathB:
			result.PathBCounts++
		case PathResultPathC:
			result.PathCCounts++
		case PathResultPathD:
			result.PathDCounts++
		case PathResultRejected:
			result.RejectedCounts++
		}
	}

	mutations := tree.StopTracking()
	result.Mutations = mutations

	root, err := tree.Root()
	if err != nil {
		return nil, err
	}
	result.NewRoot = root
	result.UpdatedBuffer = deltaBuffer

	return result, nil
}
