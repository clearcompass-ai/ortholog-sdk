package types

type SMTLeaf struct {
	Key          [32]byte
	OriginTip    LogPosition
	AuthorityTip LogPosition
}

func (l SMTLeaf) IsSelfReferential() bool {
	return l.OriginTip.Equal(l.AuthorityTip)
}
