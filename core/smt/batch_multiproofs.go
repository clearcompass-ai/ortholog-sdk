package smt

import (
	"sort"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// GenerateBatchProof generates a batch SMT multiproof for multiple keys.
// Shared path segments are deduplicated. Only non-default nodes included.
// Canonical node ordering (SDK-D13): depth ascending, position ascending.
// Two compliant implementations produce byte-identical proofs for the same input.
func (t *Tree) GenerateBatchProof(keys [][32]byte) (*types.BatchProof, error) {
	if len(keys) == 0 {
		return nil, nil
	}

	// Collect all entries.
	entries := make([]types.BatchEntry, 0, len(keys))
	for _, key := range keys {
		leaf, err := t.leaves.Get(key)
		if err != nil {
			return nil, err
		}
		entry := types.BatchEntry{Hash: key}
		if leaf != nil {
			entry.LogPos = leaf.OriginTip
		}
		entries = append(entries, entry)
	}

	// Collect all unique non-default siblings needed for all proofs.
	// Deduplication: if two keys share a path segment, the sibling is stored once.
	allSiblings := make(map[nodeKey][32]byte)

	for _, key := range keys {
		siblings, err := t.collectSiblings(key)
		if err != nil {
			return nil, err
		}
		for depth, hash := range siblings {
			nk := nodeKey{Depth: uint16(depth), Key: key}
			// Determine sibling position at this depth.
			byteIdx := uint(depth) / 8
			bitMask := byte(0x80 >> (uint(depth) % 8))
			if key[byteIdx]&bitMask == 0 {
				// Key goes left, sibling is right.
				nk.Position = 1
			} else {
				nk.Position = 0
			}
			allSiblings[nk] = hash
		}
	}

	// Convert to canonical ordering (SDK-D13): depth ascending, position ascending.
	nodes := make([]types.ProofNode, 0, len(allSiblings))
	for nk, hash := range allSiblings {
		nodes = append(nodes, types.ProofNode{
			Depth:    nk.Depth,
			Position: nk.Position,
			Hash:     hash,
		})
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Depth != nodes[j].Depth {
			return nodes[i].Depth < nodes[j].Depth
		}
		return nodes[i].Position < nodes[j].Position
	})

	return &types.BatchProof{
		SMTNodes: nodes,
		Entries:  entries,
	}, nil
}

// nodeKey uniquely identifies a node in the batch proof for deduplication.
type nodeKey struct {
	Depth    uint16
	Position uint64
	Key      [32]byte // The query key this sibling belongs to
}
