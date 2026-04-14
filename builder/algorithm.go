package builder

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// processEntry routes a single entry through the four-path algorithm.
// Implements the complete builder algorithm from the spec with all 6 fixes.
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

	// ── Commentary discriminator (Fix 1) ──────────────────────────────
	if h.TargetRoot == nil {
		if h.AuthorityPath == nil {
			return PathResultCommentary, nil
		}
		key := smt.DeriveKey(pos)
		leaf := types.SMTLeaf{
			Key:          key,
			OriginTip:    pos,
			AuthorityTip: pos,
		}
		if err := tree.SetLeaf(key, leaf); err != nil {
			return PathResultPathD, fmt.Errorf("creating leaf: %w", err)
		}
		return PathResultNewLeaf, nil
	}

	targetRoot := *h.TargetRoot

	// ── Decision 47: locality check ───────────────────────────────────
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

	// ── Evidence_Pointers cap (Decision 51) ───────────────────────────
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
		return processPathA(tree, h, pos, targetEntry, leafKey, leaf)
	case envelope.AuthorityDelegation:
		return processPathB(tree, h, pos, targetEntry, leafKey, leaf, fetcher, localLogDID)
	case envelope.AuthorityScopeAuthority:
		return processPathC(tree, h, pos, targetRoot, leafKey, leaf, fetcher, schemaRes, localLogDID, deltaBuffer)
	default:
		return PathResultPathD, nil
	}
}

// ── PATH A: Same Signer ───────────────────────────────────────────────

func processPathA(
	tree *smt.Tree,
	h *envelope.ControlHeader,
	pos types.LogPosition,
	target *envelope.Entry,
	leafKey [32]byte,
	leaf *types.SMTLeaf,
) (PathResult, error) {
	if h.SignerDID != target.Header.SignerDID {
		return PathResultPathD, nil
	}
	if err := updateOriginTip(tree, leafKey, leaf, pos); err != nil {
		return PathResultPathD, err
	}
	if h.TargetIntermediate != nil {
		if err := updateIntermediateOriginTip(tree, *h.TargetIntermediate, pos); err != nil {
			return PathResultPathD, err
		}
	}
	return PathResultPathA, nil
}

// ── PATH B: Bounded Delegation (max depth 3) ──────────────────────────
//
// Builds a chain from E_new.Signer_DID back to E_target.Signer_DID through
// delegation entries. The builder handles any valid permutation of pointers
// (SDK-D10: ordering is convention, not correctness requirement).
//
// At each step, finds an unused delegation pointer whose Delegate_DID matches
// the current expected DID. The chain starts with expectedDelegate = E_new.Signer_DID.

func processPathB(
	tree *smt.Tree,
	h *envelope.ControlHeader,
	pos types.LogPosition,
	target *envelope.Entry,
	leafKey [32]byte,
	leaf *types.SMTLeaf,
	fetcher EntryFetcher,
	localLogDID string,
) (PathResult, error) {
	if len(h.DelegationPointers) == 0 {
		return PathResultPathD, nil
	}

	targetSignerDID := target.Header.SignerDID

	// Pre-fetch and validate all delegation entries.
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
		// Delegation liveness (Fix 3): strict equality.
		dLeafKey := smt.DeriveKey(ptr)
		dLeaf, err := tree.GetLeaf(dLeafKey)
		if err != nil || dLeaf == nil {
			return PathResultPathD, nil
		}
		if !dLeaf.OriginTip.Equal(ptr) {
			return PathResultPathD, nil // Revoked or amended.
		}
		delegations = append(delegations, delegInfo{ptr: ptr, entry: entry})
	}

	// Walk: start from E_new.Signer_DID, find chain to E_target.Signer_DID.
	expectedDelegate := h.SignerDID
	visited := make(map[string]bool)

	for depth := 0; depth < 3; depth++ {
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
				// Chain connects.
				if err := updateOriginTip(tree, leafKey, leaf, pos); err != nil {
					return PathResultPathD, err
				}
				if h.TargetIntermediate != nil {
					if err := updateIntermediateOriginTip(tree, *h.TargetIntermediate, pos); err != nil {
						return PathResultPathD, err
					}
				}
				return PathResultPathB, nil
			}

			if visited[dh.SignerDID] {
				return PathResultRejected, nil // Loop detected.
			}
			visited[dh.SignerDID] = true
			expectedDelegate = dh.SignerDID
			break
		}
		if !found {
			break
		}
	}

	// Check if we ran out of depth without connecting.
	// If all 3 pointers used but chain didn't connect, depth exceeded.
	usedCount := 0
	for _, d := range delegations {
		if d.used {
			usedCount++
		}
	}
	if usedCount >= 3 {
		return PathResultRejected, nil // Depth > 3.
	}

	return PathResultPathD, nil
}

// ── PATH C: Scope Authority ───────────────────────────────────────────

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

	// Fetch scope leaf to get current version.
	scopeLeafKey := smt.DeriveKey(*h.ScopePointer)
	scopeLeaf, err := tree.GetLeaf(scopeLeafKey)
	if err != nil || scopeLeaf == nil {
		return PathResultPathD, nil
	}

	// Read current scope version via Origin_Tip.
	currentScopeMeta, err := fetcher.Fetch(scopeLeaf.OriginTip)
	if err != nil || currentScopeMeta == nil {
		return PathResultPathD, nil
	}
	currentScope, err := envelope.Deserialize(currentScopeMeta.CanonicalBytes)
	if err != nil {
		return PathResultPathD, nil
	}

	// Verify signer membership.
	if !currentScope.Header.AuthoritySetContains(h.SignerDID) {
		return PathResultPathD, nil
	}

	// Verify Approval_Pointers.
	if len(h.ApprovalPointers) > 0 {
		if err := verifyApprovalPointers(h.ApprovalPointers, currentScope, fetcher, localLogDID); err != nil {
			return PathResultRejected, nil
		}
	}

	// Verify Prior_Authority (OCC).
	if err := verifyPriorAuthority(h, targetRoot, leaf, deltaBuffer, schemaRes, fetcher); err != nil {
		return PathResultRejected, nil
	}

	// ── Lane selection (Fix 2: two-condition discriminator) ────────────
	// Scope_Pointer == Target_Root AND Authority_Set present -> OriginTip
	// All else -> AuthorityTip
	isScopeAmendment := h.ScopePointer.Equal(targetRoot) && len(h.AuthoritySet) > 0

	if isScopeAmendment {
		if err := updateOriginTip(tree, leafKey, leaf, pos); err != nil {
			return PathResultPathD, err
		}
		if h.TargetIntermediate != nil {
			if err := updateIntermediateOriginTip(tree, *h.TargetIntermediate, pos); err != nil {
				return PathResultPathD, err
			}
		}
	} else {
		if err := updateAuthorityTip(tree, leafKey, leaf, pos, deltaBuffer); err != nil {
			return PathResultPathD, err
		}
		if h.TargetIntermediate != nil {
			intKey := smt.DeriveKey(*h.TargetIntermediate)
			intLeaf, err := tree.GetLeaf(intKey)
			if err == nil && intLeaf != nil {
				newLeaf := *intLeaf
				newLeaf.AuthorityTip = pos
				_ = tree.SetLeaf(intKey, newLeaf)
			}
		}
	}

	return PathResultPathC, nil
}

// verifyApprovalPointers verifies each approval entry's signer is in the authority set.
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
