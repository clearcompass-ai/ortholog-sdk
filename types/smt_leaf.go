package types

// SMTLeaf is the fixed-width leaf in the Sparse Merkle Tree.
// Two orthogonal lanes: Origin tracks content/validity, Authority tracks enforcement.
// Both tips initialized to self (the root entity's own position) on creation.
type SMTLeaf struct {
	Key          [32]byte    // SHA-256(log_position of root entity)
	OriginTip    LogPosition // O(1) via path compression
	AuthorityTip LogPosition // O(A) via Prior_Authority chain, compactable
}

// IsSelfReferential returns true if both tips point to the same position,
// which is the initial state ("this entry is its own current version and
// has no enforcement actions against it").
func (l SMTLeaf) IsSelfReferential() bool {
	return l.OriginTip.Equal(l.AuthorityTip)
}
