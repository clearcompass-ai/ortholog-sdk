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
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/scope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// maxDelegationDepth is the protocol cap on delegation chain length.
const maxDelegationDepth = 3

func processEntry(
	tree *smt.Tree,
	entry *envelope.Entry,
	pos types.LogPosition,
	fetcher types.EntryFetcher,
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
	fetcher types.EntryFetcher,
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
	fetcher types.EntryFetcher,
	schemaRes SchemaResolver,
	localLogDID string,
	deltaBuffer *DeltaWindowBuffer,
) (PathResult, error) {
	if h.ScopePointer == nil || h.ScopePointer.LogDID != localLogDID {
		return PathResultPathD, nil
	}

	// Decision 52: resolve the governing AuthoritySet via the shared
	// scope-history primitive. Scope-creation entries have no
	// Prior_Authority — they ARE the scope entry, so a query at the
	// scope's own position returns the creation's own AuthoritySet
	// (the set the creator is declaring). All other Path C entries
	// resolve at their Prior_Authority: the observation the signer
	// committed to at signing time.
	queryPos := *h.ScopePointer
	if h.PriorAuthority != nil {
		queryPos = *h.PriorAuthority
	}
	// Fail fast when the Prior_Authority is itself on a foreign log
	// — the scope primitive would refuse, and PathD is the right
	// response for any locality violation.
	if queryPos.LogDID != localLogDID {
		return PathResultPathD, nil
	}

	authoritySet, err := scope.AuthorizedSetAtPosition(*h.ScopePointer, queryPos, fetcher, tree)
	if err != nil {
		// Structural violations of Decision 52 — cycle, cross-log
		// walk, empty set, malformed entry, walk-too-deep, or the
		// caller claiming to observe a scope state that predates
		// the scope's own creation — are admission-level rejections:
		// the entry is not valid under any path and should be
		// flagged rather than quietly dropped.
		//
		// Transient or legitimate absence (the scope's leaf is
		// not yet in this tree, or an entry along the walk is not
		// yet in the fetcher) degrades to PathD so the builder
		// continues processing. This matches the pre-Decision-52
		// behaviour for missing scope state.
		switch {
		case errors.Is(err, scope.ErrScopeCycle),
			errors.Is(err, scope.ErrCrossLogScopeHistory),
			errors.Is(err, scope.ErrScopeEmptySet),
			errors.Is(err, scope.ErrScopeEntryMalformed),
			errors.Is(err, scope.ErrScopeWalkTooDeep),
			errors.Is(err, scope.ErrScopePositionUnknown):
			return PathResultRejected, err
		default:
			return PathResultPathD, nil
		}
	}
	if _, ok := authoritySet[h.SignerDID]; !ok {
		return PathResultPathD, nil
	}

	if len(h.ApprovalPointers) > 0 {
		if err := verifyApprovalPointersAgainstSet(h.ApprovalPointers, authoritySet, fetcher, localLogDID); err != nil {
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

// verifyApprovalPointersAgainstSet validates each approval pointer's
// signer against an already-resolved AuthoritySet. Decision 52: the
// caller derives the set via core/scope once, then passes it in;
// every approval is evaluated against the same time-indexed view.
func verifyApprovalPointersAgainstSet(
	pointers []types.LogPosition,
	authoritySet map[string]struct{},
	fetcher types.EntryFetcher,
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
		if _, ok := authoritySet[approval.Header.SignerDID]; !ok {
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
