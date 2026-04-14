package builder

import (
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func updateOriginTip(tree *smt.Tree, leafKey [32]byte, leaf *types.SMTLeaf, newTip types.LogPosition) error {
	updated := *leaf; updated.OriginTip = newTip; return tree.SetLeaf(leafKey, updated)
}

func updateAuthorityTip(tree *smt.Tree, leafKey [32]byte, leaf *types.SMTLeaf, newTip types.LogPosition, buffer *DeltaWindowBuffer) error {
	updated := *leaf; updated.AuthorityTip = newTip
	if buffer != nil { buffer.Record(leafKey, newTip) }
	return tree.SetLeaf(leafKey, updated)
}

func updateIntermediateOriginTip(tree *smt.Tree, intermediate types.LogPosition, newTip types.LogPosition) error {
	intKey := smt.DeriveKey(intermediate)
	intLeaf, err := tree.GetLeaf(intKey)
	if err != nil { return err }
	if intLeaf == nil { return nil }
	updated := *intLeaf; updated.OriginTip = newTip; return tree.SetLeaf(intKey, updated)
}
