package builder

import (
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// updateOriginTip updates the Origin_Tip of the leaf at leafKey.
// Used by Path A, Path B, and Path C (scope amendment execution).
func updateOriginTip(tree *smt.Tree, leafKey [32]byte, leaf *types.SMTLeaf, newTip types.LogPosition) error {
	updated := *leaf
	updated.OriginTip = newTip
	return tree.SetLeaf(leafKey, updated)
}

// updateAuthorityTip updates the Authority_Tip of the leaf at leafKey.
// Used by Path C (enforcement, contest, override, snapshot).
// Also records the new tip in the delta-window buffer for commutative OCC.
func updateAuthorityTip(tree *smt.Tree, leafKey [32]byte, leaf *types.SMTLeaf, newTip types.LogPosition, buffer *DeltaWindowBuffer) error {
	updated := *leaf
	updated.AuthorityTip = newTip
	if buffer != nil {
		buffer.Record(leafKey, newTip)
	}
	return tree.SetLeaf(leafKey, updated)
}

// updateIntermediateOriginTip updates the Origin_Tip of the Target_Intermediate leaf.
// Path compression: both Target_Root and Target_Intermediate get the same tip update.
// O(1) from any entry to its terminal state.
func updateIntermediateOriginTip(tree *smt.Tree, intermediate types.LogPosition, newTip types.LogPosition) error {
	intKey := smt.DeriveKey(intermediate)
	intLeaf, err := tree.GetLeaf(intKey)
	if err != nil {
		return err
	}
	if intLeaf == nil {
		// Intermediate leaf doesn't exist yet. This shouldn't happen for valid entries,
		// but handle gracefully — the builder doesn't abort on individual entry issues.
		return nil
	}
	updated := *intLeaf
	updated.OriginTip = newTip
	return tree.SetLeaf(intKey, updated)
}
