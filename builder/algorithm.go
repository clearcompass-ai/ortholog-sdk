/*
Package builder — algorithm.go implements per-entry path routing using
the compute-then-apply pattern.

Each path processor runs in two phases:

 1. Compute phase (pure, no side effects):
    Validates invariants and builds a []leafUpdate list. If any
    validation fails, zero writes have happened and the entry is
    rejected cleanly.

 2. Apply phase:
    applyLeafUpdates writes each update to the SMT in sequence and
    records DeltaWindowBuffer entries after successful commits.

This structure eliminates validation-failure partial mutations: you
cannot have the intermediate leaf advanced but the main leaf left
behind because the main leaf's validation rejected. All validation
completes before any write.
*/
package builder

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// maxDelegationDepth is the protocol cap on delegation chain length.
const maxDelegationDepth = 3

func processEntry(
	tree *smt.Tree,
	entry *envelope.Entry,
	pos types.LogPosition,
	fetcher EntryFetcher,
	schemaRes SchemaResolver,
	localLogDID string,
	deltaBuffer *DeltaWindowBuffer,
) (PathResult, error) {
	h := &entry.Header

	// Commentary or new leaf.
	if h.TargetRoot == nil {
		if h.AuthorityPath == nil {
			return PathResultCommentary, nil
		}
		key := smt.DeriveKey(pos)
		leaf := types.SMTLeaf{Key: key, OriginTip: pos, AuthorityTip: pos}
		// Route through the shared atomicity boundary so every leaf
		// mutation in the builder flows through a single primitive
		// (ORTHO-BUG-002). New-leaf creation does not participate in
		// the Δ-window, so the buffer is nil.
		if err := applyLeafUpdates(tree, nil, []leafUpdate{{key: key, leaf: leaf}}); err != nil {
			return PathResultPathD, fmt.Errorf("creating leaf: %w", err)
		}
		return PathResultNewLeaf, nil
	}

	targetRoot := *h.TargetRoot

	// Locality (Decision 47).
	if targetRoot.LogDID != localLogDID {
		return PathResultPathD, nil
	}

	targetMeta, err := fetcher.Fetch(targetRoot)
	if err != nil || targetMeta == nil {
		return PathResultPathD, nil
	}
	targetEntry, err := envelope.Deserialize(targetMeta.CanonicalBytes)
	if err != nil {
		return PathResultPathD, nil
	}
	leafKey := smt.DeriveKey(targetRoot)
	leaf, err := tree.GetLeaf(leafKey)
	if err != nil || leaf == nil {
		return PathResultPathD, nil
	}

	// Evidence cap with shape-based snapshot exemption.
	if len(h.EvidencePointers) > envelope.MaxEvidencePointers {
		if !isAuthoritySnapshot(h) {
			return PathResultRejected, nil
		}
	}

	if h.AuthorityPath == nil {
		return PathResultPathD, nil
	}

	switch *h.AuthorityPath {
	case envelope.AuthoritySameSigner:
		return processPathA(tree, h, pos, targetEntry, leafKey, leaf, localLogDID, deltaBuffer)
	case envelope.AuthorityDelegation:
		return processPathB(tree, h, pos, targetEntry, leafKey, leaf, fetcher, localLogDID, deltaBuffer)
	case envelope.AuthorityScopeAuthority:
		return processPathC(tree, h, pos, targetRoot, leafKey, leaf, fetcher, schemaRes, localLogDID, deltaBuffer)
	default:
		return PathResultPathD, nil
	}
}

// ─────────────────────────────────────────────────────────────────────
// Path A — same signer
// ─────────────────────────────────────────────────────────────────────

func processPathA(
	tree *smt.Tree,
	h *envelope.ControlHeader,
	pos types.LogPosition,
	target *envelope.Entry,
	leafKey [32]byte,
	leaf *types.SMTLeaf,
	localLogDID string,
	deltaBuffer *DeltaWindowBuffer,
) (PathResult, error) {
	if h.SignerDID != target.Header.SignerDID {
		return PathResultPathD, nil
	}

	// Compute phase — no SMT writes.
	updates := make([]leafUpdate, 0, 2)
	if h.TargetIntermediate != nil {
		u, err := computeIntermediateOriginTip(tree, *h.TargetIntermediate, pos, localLogDID)
		if err != nil {
			return PathResultPathD, err
		}
		updates = append(updates, u)
	}
	u, err := computeOriginTipUpdate(leafKey, leaf, pos)
	if err != nil {
		return PathResultPathD, err
	}
	updates = append(updates, u)

	// Apply phase — writes only after all validation passed.
	if err := applyLeafUpdates(tree, deltaBuffer, updates); err != nil {
		return PathResultPathD, err
	}
	return PathResultPathA, nil
}

// ─────────────────────────────────────────────────────────────────────
// Path B — delegation chain
// ─────────────────────────────────────────────────────────────────────

func processPathB(
	tree *smt.Tree,
	h *envelope.ControlHeader,
	pos types.LogPosition,
	target *envelope.Entry,
	leafKey [32]byte,
	leaf *types.SMTLeaf,
	fetcher EntryFetcher,
	localLogDID string,
	deltaBuffer *DeltaWindowBuffer,
) (PathResult, error) {
	if len(h.DelegationPointers) == 0 {
		return PathResultPathD, nil
	}

	targetSignerDID := target.Header.SignerDID

	type delegInfo struct {
		ptr   types.LogPosition
		entry *envelope.Entry
		used  bool
	}
	delegations := make([]delegInfo, 0, len(h.DelegationPointers))

	for _, ptr := range h.DelegationPointers {
		if ptr.LogDID != localLogDID {
			return PathResultPathD, nil
		}
		meta, err := fetcher.Fetch(ptr)
		if err != nil || meta == nil {
			return PathResultPathD, nil
		}
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil || entry.Header.DelegateDID == nil {
			return PathResultPathD, nil
		}
		dLeafKey := smt.DeriveKey(ptr)
		dLeaf, err := tree.GetLeaf(dLeafKey)
		if err != nil || dLeaf == nil {
			return PathResultPathD, nil
		}
		if !dLeaf.OriginTip.Equal(ptr) {
			return PathResultPathD, nil
		}
		delegations = append(delegations, delegInfo{ptr: ptr, entry: entry})
	}

	expectedDelegate := h.SignerDID
	visited := make(map[string]bool)

	for depth := 0; depth < maxDelegationDepth; depth++ {
		found := false
		for i := range delegations {
			if delegations[i].used {
				continue
			}
			dh := &delegations[i].entry.Header
			if *dh.DelegateDID != expectedDelegate {
				continue
			}
			delegations[i].used = true
			found = true

			if dh.SignerDID == targetSignerDID {
				// Chain connects. Compute mutations.
				updates := make([]leafUpdate, 0, 2)
				if h.TargetIntermediate != nil {
					u, err := computeIntermediateOriginTip(tree, *h.TargetIntermediate, pos, localLogDID)
					if err != nil {
						return PathResultPathD, err
					}
					updates = append(updates, u)
				}
				u, err := computeOriginTipUpdate(leafKey, leaf, pos)
				if err != nil {
					return PathResultPathD, err
				}
				updates = append(updates, u)

				// Apply.
				if err := applyLeafUpdates(tree, deltaBuffer, updates); err != nil {
					return PathResultPathD, err
				}
				return PathResultPathB, nil
			}

			if visited[dh.SignerDID] {
				return PathResultRejected, nil
			}
			visited[dh.SignerDID] = true
			expectedDelegate = dh.SignerDID
			break
		}
		if !found {
			break
		}
	}

	usedCount := 0
	for _, d := range delegations {
		if d.used {
			usedCount++
		}
	}
	if usedCount >= maxDelegationDepth {
		return PathResultRejected, nil
	}
	return PathResultPathD, nil
}

// ─────────────────────────────────────────────────────────────────────
// Path C — scope authority
// ─────────────────────────────────────────────────────────────────────

func processPathC(
	tree *smt.Tree,
	h *envelope.ControlHeader,
	pos types.LogPosition,
	targetRoot types.LogPosition,
	leafKey [32]byte,
	leaf *types.SMTLeaf,
	fetcher EntryFetcher,
	schemaRes SchemaResolver,
	localLogDID string,
	deltaBuffer *DeltaWindowBuffer,
) (PathResult, error) {
	if h.ScopePointer == nil || h.ScopePointer.LogDID != localLogDID {
		return PathResultPathD, nil
	}

	scopeLeafKey := smt.DeriveKey(*h.ScopePointer)
	scopeLeaf, err := tree.GetLeaf(scopeLeafKey)
	if err != nil || scopeLeaf == nil {
		return PathResultPathD, nil
	}
	currentScopeMeta, err := fetcher.Fetch(scopeLeaf.OriginTip)
	if err != nil || currentScopeMeta == nil {
		return PathResultPathD, nil
	}
	currentScope, err := envelope.Deserialize(currentScopeMeta.CanonicalBytes)
	if err != nil {
		return PathResultPathD, nil
	}
	if !currentScope.Header.AuthoritySetContains(h.SignerDID) {
		return PathResultPathD, nil
	}

	if len(h.ApprovalPointers) > 0 {
		if err := verifyApprovalPointers(h.ApprovalPointers, currentScope, fetcher, localLogDID); err != nil {
			return PathResultRejected, nil
		}
	}

	if err := verifyPriorAuthority(h, targetRoot, leaf, deltaBuffer, schemaRes, fetcher); err != nil {
		return PathResultRejected, nil
	}

	isScopeAmendment := h.ScopePointer.Equal(targetRoot) && len(h.AuthoritySet) > 0

	// Compute phase — all validation, no writes.
	updates := make([]leafUpdate, 0, 2)

	if isScopeAmendment {
		if h.TargetIntermediate != nil {
			u, err := computeIntermediateOriginTip(tree, *h.TargetIntermediate, pos, localLogDID)
			if err != nil {
				return PathResultPathD, err
			}
			updates = append(updates, u)
		}
		u, err := computeOriginTipUpdate(leafKey, leaf, pos)
		if err != nil {
			return PathResultPathD, err
		}
		updates = append(updates, u)
	} else {
		if h.TargetIntermediate != nil {
			u, err := computeIntermediateAuthorityTip(tree, *h.TargetIntermediate, pos, localLogDID)
			if err != nil {
				return PathResultPathD, err
			}
			updates = append(updates, u)
		}
		u, err := computeAuthorityTipUpdate(leafKey, leaf, pos)
		if err != nil {
			return PathResultPathD, err
		}
		updates = append(updates, u)
	}

	// Apply phase.
	if err := applyLeafUpdates(tree, deltaBuffer, updates); err != nil {
		return PathResultPathD, err
	}
	return PathResultPathC, nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func verifyApprovalPointers(
	pointers []types.LogPosition,
	currentScope *envelope.Entry,
	fetcher EntryFetcher,
	localLogDID string,
) error {
	for i, ptr := range pointers {
		if ptr.LogDID != localLogDID {
			return fmt.Errorf("approval %d: foreign log", i)
		}
		meta, err := fetcher.Fetch(ptr)
		if err != nil || meta == nil {
			return fmt.Errorf("approval %d: not found", i)
		}
		approval, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			return fmt.Errorf("approval %d: %w", i, err)
		}
		if !currentScope.Header.AuthoritySetContains(approval.Header.SignerDID) {
			return fmt.Errorf("approval %d: signer not in authority set", i)
		}
	}
	return nil
}

func isAuthoritySnapshot(h *envelope.ControlHeader) bool {
	if h.AuthorityPath == nil || *h.AuthorityPath != envelope.AuthorityScopeAuthority {
		return false
	}
	return h.TargetRoot != nil && h.PriorAuthority != nil
}
