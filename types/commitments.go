package types

type SMTDerivationCommitment struct {
	LogRangeStart LogPosition
	LogRangeEnd   LogPosition
	PriorSMTRoot  [32]byte
	PostSMTRoot   [32]byte
	Mutations     []LeafMutation
	MutationCount uint32
}

type LeafMutation struct {
	LeafKey         [32]byte
	OldOriginTip    LogPosition
	NewOriginTip    LogPosition
	OldAuthorityTip LogPosition
	NewAuthorityTip LogPosition
}
