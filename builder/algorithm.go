package builder

import (
	"fmt"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func processEntry(tree *smt.Tree, entry *envelope.Entry, pos types.LogPosition, fetcher EntryFetcher, schemaRes SchemaResolver, localLogDID string, deltaBuffer *DeltaWindowBuffer) (PathResult, error) {
	h := &entry.Header
	if h.TargetRoot == nil {
		if h.AuthorityPath == nil { return PathResultCommentary, nil }
		key := smt.DeriveKey(pos)
		leaf := types.SMTLeaf{Key: key, OriginTip: pos, AuthorityTip: pos}
		if err := tree.SetLeaf(key, leaf); err != nil { return PathResultPathD, fmt.Errorf("creating leaf: %w", err) }
		return PathResultNewLeaf, nil
	}
	targetRoot := *h.TargetRoot
	if targetRoot.LogDID != localLogDID { return PathResultPathD, nil }
	targetMeta, err := fetcher.Fetch(targetRoot)
	if err != nil || targetMeta == nil { return PathResultPathD, nil }
	targetEntry, err := envelope.Deserialize(targetMeta.CanonicalBytes)
	if err != nil { return PathResultPathD, nil }
	leafKey := smt.DeriveKey(targetRoot)
	leaf, err := tree.GetLeaf(leafKey)
	if err != nil || leaf == nil { return PathResultPathD, nil }
	if len(h.EvidencePointers) > envelope.MaxEvidencePointers {
		if !isAuthoritySnapshot(h) { return PathResultRejected, nil }
	}
	if h.AuthorityPath == nil { return PathResultPathD, nil }
	switch *h.AuthorityPath {
	case envelope.AuthoritySameSigner: return processPathA(tree, h, pos, targetEntry, leafKey, leaf)
	case envelope.AuthorityDelegation: return processPathB(tree, h, pos, targetEntry, leafKey, leaf, fetcher, localLogDID)
	case envelope.AuthorityScopeAuthority: return processPathC(tree, h, pos, targetRoot, leafKey, leaf, fetcher, schemaRes, localLogDID, deltaBuffer)
	default: return PathResultPathD, nil
	}
}

func processPathA(tree *smt.Tree, h *envelope.ControlHeader, pos types.LogPosition, target *envelope.Entry, leafKey [32]byte, leaf *types.SMTLeaf) (PathResult, error) {
	if h.SignerDID != target.Header.SignerDID { return PathResultPathD, nil }
	if err := updateOriginTip(tree, leafKey, leaf, pos); err != nil { return PathResultPathD, err }
	if h.TargetIntermediate != nil {
		if err := updateIntermediateOriginTip(tree, *h.TargetIntermediate, pos); err != nil { return PathResultPathD, err }
	}
	return PathResultPathA, nil
}

func processPathB(tree *smt.Tree, h *envelope.ControlHeader, pos types.LogPosition, target *envelope.Entry, leafKey [32]byte, leaf *types.SMTLeaf, fetcher EntryFetcher, localLogDID string) (PathResult, error) {
	if len(h.DelegationPointers) == 0 { return PathResultPathD, nil }
	targetSignerDID := target.Header.SignerDID
	type delegInfo struct { ptr types.LogPosition; entry *envelope.Entry; used bool }
	delegations := make([]delegInfo, 0, len(h.DelegationPointers))
	for _, ptr := range h.DelegationPointers {
		if ptr.LogDID != localLogDID { return PathResultPathD, nil }
		meta, err := fetcher.Fetch(ptr)
		if err != nil || meta == nil { return PathResultPathD, nil }
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil || entry.Header.DelegateDID == nil { return PathResultPathD, nil }
		dLeafKey := smt.DeriveKey(ptr)
		dLeaf, err := tree.GetLeaf(dLeafKey)
		if err != nil || dLeaf == nil { return PathResultPathD, nil }
		if !dLeaf.OriginTip.Equal(ptr) { return PathResultPathD, nil }
		delegations = append(delegations, delegInfo{ptr: ptr, entry: entry})
	}
	expectedDelegate := h.SignerDID
	visited := make(map[string]bool)
	for depth := 0; depth < 3; depth++ {
		found := false
		for i := range delegations {
			if delegations[i].used { continue }
			dh := &delegations[i].entry.Header
			if *dh.DelegateDID != expectedDelegate { continue }
			delegations[i].used = true; found = true
			if dh.SignerDID == targetSignerDID {
				if err := updateOriginTip(tree, leafKey, leaf, pos); err != nil { return PathResultPathD, err }
				if h.TargetIntermediate != nil {
					if err := updateIntermediateOriginTip(tree, *h.TargetIntermediate, pos); err != nil { return PathResultPathD, err }
				}
				return PathResultPathB, nil
			}
			if visited[dh.SignerDID] { return PathResultRejected, nil }
			visited[dh.SignerDID] = true; expectedDelegate = dh.SignerDID; break
		}
		if !found { break }
	}
	usedCount := 0
	for _, d := range delegations { if d.used { usedCount++ } }
	if usedCount >= 3 { return PathResultRejected, nil }
	return PathResultPathD, nil
}

func processPathC(tree *smt.Tree, h *envelope.ControlHeader, pos types.LogPosition, targetRoot types.LogPosition, leafKey [32]byte, leaf *types.SMTLeaf, fetcher EntryFetcher, schemaRes SchemaResolver, localLogDID string, deltaBuffer *DeltaWindowBuffer) (PathResult, error) {
	if h.ScopePointer == nil || h.ScopePointer.LogDID != localLogDID { return PathResultPathD, nil }
	scopeLeafKey := smt.DeriveKey(*h.ScopePointer)
	scopeLeaf, err := tree.GetLeaf(scopeLeafKey)
	if err != nil || scopeLeaf == nil { return PathResultPathD, nil }
	currentScopeMeta, err := fetcher.Fetch(scopeLeaf.OriginTip)
	if err != nil || currentScopeMeta == nil { return PathResultPathD, nil }
	currentScope, err := envelope.Deserialize(currentScopeMeta.CanonicalBytes)
	if err != nil { return PathResultPathD, nil }
	if !currentScope.Header.AuthoritySetContains(h.SignerDID) { return PathResultPathD, nil }
	if len(h.ApprovalPointers) > 0 {
		if err := verifyApprovalPointers(h.ApprovalPointers, currentScope, fetcher, localLogDID); err != nil { return PathResultRejected, nil }
	}
	if err := verifyPriorAuthority(h, targetRoot, leaf, deltaBuffer, schemaRes, fetcher); err != nil { return PathResultRejected, nil }
	isScopeAmendment := h.ScopePointer.Equal(targetRoot) && len(h.AuthoritySet) > 0
	if isScopeAmendment {
		if err := updateOriginTip(tree, leafKey, leaf, pos); err != nil { return PathResultPathD, err }
		if h.TargetIntermediate != nil {
			if err := updateIntermediateOriginTip(tree, *h.TargetIntermediate, pos); err != nil { return PathResultPathD, err }
		}
	} else {
		if err := updateAuthorityTip(tree, leafKey, leaf, pos, deltaBuffer); err != nil { return PathResultPathD, err }
		if h.TargetIntermediate != nil {
			intKey := smt.DeriveKey(*h.TargetIntermediate)
			intLeaf, err := tree.GetLeaf(intKey)
			if err == nil && intLeaf != nil {
				newLeaf := *intLeaf; newLeaf.AuthorityTip = pos; _ = tree.SetLeaf(intKey, newLeaf)
			}
		}
	}
	return PathResultPathC, nil
}

func verifyApprovalPointers(pointers []types.LogPosition, currentScope *envelope.Entry, fetcher EntryFetcher, localLogDID string) error {
	for i, ptr := range pointers {
		if ptr.LogDID != localLogDID { return fmt.Errorf("approval %d: foreign log", i) }
		meta, err := fetcher.Fetch(ptr)
		if err != nil || meta == nil { return fmt.Errorf("approval %d: not found", i) }
		approval, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil { return fmt.Errorf("approval %d: %w", i, err) }
		if !currentScope.Header.AuthoritySetContains(approval.Header.SignerDID) { return fmt.Errorf("approval %d: signer not in authority set", i) }
	}
	return nil
}

func isAuthoritySnapshot(h *envelope.ControlHeader) bool {
	if h.AuthorityPath == nil || *h.AuthorityPath != envelope.AuthorityScopeAuthority { return false }
	return h.TargetRoot != nil && h.PriorAuthority != nil
}
