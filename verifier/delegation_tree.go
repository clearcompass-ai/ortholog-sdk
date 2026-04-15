/*
Package verifier — delegation_tree.go walks the delegation tree rooted at
an entity position and enumerates all live delegations. Used by the judicial
network's delegation/roster_sync.go for building the complete officer roster.

Unlike VerifyDelegationProvenance (authority_evaluator.go), which walks a
specific chain of Delegation_Pointers for one entry, WalkDelegationTree
discovers ALL delegations issued by a signer and builds the full tree.

The tree is built breadth-first:
  1. Start at root entity → read SignerDID
  2. Query all delegation entries where Signer_DID == rootSignerDID
  3. For each live delegation → add to tree, recurse on Delegate_DID
  4. Max depth 3 (protocol maximum for delegation chains)

The same DID can hold delegations across multiple divisions, courts, and
networks (cross-network officer doc, Variant 1). WalkDelegationTree handles
multiple delegation entries for the same Delegate_DID on the same log.

Consumed by:
  - judicial-network/delegation/roster_sync.go
  - Domain administration tools (delegation audit)
*/
package verifier

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// DelegationQuerier discovers delegation entries by signer DID.
// Satisfied by log.OperatorQueryAPI.QueryBySignerDID (structural typing).
type DelegationQuerier interface {
	QueryBySignerDID(did string) ([]types.EntryWithMetadata, error)
}

// DelegationNode represents one node in the delegation tree.
type DelegationNode struct {
	// Position is the LogPosition of this delegation entry.
	// For the root node, this is the root entity position.
	Position types.LogPosition

	// SignerDID is who created this delegation (the grantor).
	SignerDID string

	// DelegateDID is who received delegated authority.
	// Empty for the root entity node.
	DelegateDID string

	// IsLive is true if the delegation leaf's OriginTip equals Position.
	IsLive bool

	// RevokedAt is the OriginTip position if the delegation was revoked.
	RevokedAt types.LogPosition

	// Depth is the distance from the root entity (root=0, first delegation=1).
	Depth int

	// Children are delegations issued by this node's DelegateDID.
	Children []*DelegationNode

	// RawPayload is the Domain Payload of the delegation entry.
	// The caller reads scope_limit and other domain-specific fields.
	// The SDK does not interpret Domain Payload (SDK-D6).
	RawPayload []byte
}

// DelegationTree is the complete delegation tree rooted at an entity.
type DelegationTree struct {
	// Root is the root entity node. Its Children are first-level delegations.
	Root *DelegationNode

	// TotalNodes is the total number of nodes including root.
	TotalNodes int

	// LiveCount is the number of live (non-revoked) delegation nodes.
	LiveCount int

	// MaxDepthReached is the deepest level found in the tree.
	MaxDepthReached int
}

// WalkDelegationTreeParams configures the tree walk.
type WalkDelegationTreeParams struct {
	// RootEntityPos is the log position of the root entity.
	RootEntityPos types.LogPosition

	// Fetcher reads entries by position.
	Fetcher EntryFetcher

	// LeafReader reads SMT leaf state for liveness checks.
	LeafReader smt.LeafReader

	// Querier discovers delegations by signer DID.
	// Satisfied by OperatorQueryAPI (structural typing).
	Querier DelegationQuerier

	// MaxDepth overrides the default protocol maximum (3).
	// 0 or negative → default 3.
	MaxDepth int
}

// maxProtocolDelegationDepth is the protocol's maximum delegation chain depth.
const maxProtocolDelegationDepth = 3

// ─────────────────────────────────────────────────────────────────────
// WalkDelegationTree
// ─────────────────────────────────────────────────────────────────────

// WalkDelegationTree builds the complete delegation tree rooted at an
// entity position. The tree is built breadth-first, respecting the
// protocol's maximum delegation depth (3).
//
// The function:
//  1. Fetches the root entity to determine its SignerDID
//  2. Queries for all delegation entries signed by that DID
//  3. For each delegation: checks liveness, reads payload, adds to tree
//  4. Recursively discovers delegations issued by each delegate
//  5. Returns the complete tree with liveness annotations
//
// Cycle detection: if a DelegateDID appears as a signer at a deeper
// level in its own ancestor chain, the branch is pruned.
func WalkDelegationTree(p WalkDelegationTreeParams) (*DelegationTree, error) {
	maxDepth := p.MaxDepth
	if maxDepth <= 0 {
		maxDepth = maxProtocolDelegationDepth
	}

	// 1. Fetch root entity.
	rootMeta, err := p.Fetcher.Fetch(p.RootEntityPos)
	if err != nil || rootMeta == nil {
		return nil, fmt.Errorf("verifier/delegation_tree: root entity not found at %s", p.RootEntityPos)
	}
	rootEntry, err := envelope.Deserialize(rootMeta.CanonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("verifier/delegation_tree: deserialize root: %w", err)
	}

	rootNode := &DelegationNode{
		Position:  p.RootEntityPos,
		SignerDID: rootEntry.Header.SignerDID,
		IsLive:    true, // Root entity liveness not checked here (use EvaluateOrigin).
		Depth:     0,
	}

	tree := &DelegationTree{
		Root:       rootNode,
		TotalNodes: 1,
	}

	// 2. BFS — build tree level by level.
	ancestors := map[string]bool{rootEntry.Header.SignerDID: true}
	expandLevel(rootNode, rootEntry.Header.SignerDID, p, ancestors, maxDepth, tree)

	return tree, nil
}

// expandLevel discovers delegations at the next level of the tree.
func expandLevel(
	parent *DelegationNode,
	signerDID string,
	p WalkDelegationTreeParams,
	ancestors map[string]bool,
	maxDepth int,
	tree *DelegationTree,
) {
	if parent.Depth >= maxDepth {
		return
	}

	// Query for all delegation entries signed by this DID.
	entries, err := p.Querier.QueryBySignerDID(signerDID)
	if err != nil {
		return // Query failure — prune this branch silently.
	}

	for _, meta := range entries {
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			continue
		}

		// Only delegation entries (those with DelegateDID set).
		if entry.Header.DelegateDID == nil {
			continue
		}

		delegateDID := *entry.Header.DelegateDID
		childDepth := parent.Depth + 1

		// Cycle detection: skip if this delegate is already an ancestor.
		if ancestors[delegateDID] {
			continue
		}

		// Check liveness: delegation leaf's OriginTip == delegation position.
		delegPos := meta.Position
		node := &DelegationNode{
			Position:    delegPos,
			SignerDID:   entry.Header.SignerDID,
			DelegateDID: delegateDID,
			Depth:       childDepth,
			RawPayload:  entry.DomainPayload,
		}

		delegLeafKey := smt.DeriveKey(delegPos)
		delegLeaf, leafErr := p.LeafReader.Get(delegLeafKey)
		if leafErr != nil || delegLeaf == nil {
			node.IsLive = false
		} else if delegLeaf.OriginTip.Equal(delegPos) {
			node.IsLive = true
			tree.LiveCount++
		} else {
			node.IsLive = false
			node.RevokedAt = delegLeaf.OriginTip
		}

		parent.Children = append(parent.Children, node)
		tree.TotalNodes++
		if childDepth > tree.MaxDepthReached {
			tree.MaxDepthReached = childDepth
		}

		// Recurse: discover delegations issued by this delegate.
		if childDepth < maxDepth {
			childAncestors := copyAncestors(ancestors)
			childAncestors[delegateDID] = true
			expandLevel(node, delegateDID, p, childAncestors, maxDepth, tree)
		}
	}
}

// copyAncestors creates a copy of the ancestor set for branch isolation.
func copyAncestors(src map[string]bool) map[string]bool {
	dst := make(map[string]bool, len(src)+1)
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// ─────────────────────────────────────────────────────────────────────
// Tree traversal helpers
// ─────────────────────────────────────────────────────────────────────

// FlattenTree returns all delegation nodes in the tree as a flat slice
// (breadth-first order). The root entity node is included at index 0.
func FlattenTree(tree *DelegationTree) []*DelegationNode {
	if tree == nil || tree.Root == nil {
		return nil
	}
	var result []*DelegationNode
	queue := []*DelegationNode{tree.Root}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		result = append(result, node)
		queue = append(queue, node.Children...)
	}
	return result
}

// LiveDelegations returns only live (non-revoked) delegation nodes,
// excluding the root entity. Useful for building the active officer roster.
func LiveDelegations(tree *DelegationTree) []*DelegationNode {
	all := FlattenTree(tree)
	var live []*DelegationNode
	for _, node := range all {
		if node.Depth > 0 && node.IsLive {
			live = append(live, node)
		}
	}
	return live
}
