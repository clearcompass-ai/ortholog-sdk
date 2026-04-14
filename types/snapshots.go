package types

type AuthoritySnapshotRef struct {
	TargetRoot       LogPosition
	EvidencePointers []LogPosition
	PriorAuthority   LogPosition
}
