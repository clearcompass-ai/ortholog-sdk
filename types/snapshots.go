package types

// AuthoritySnapshotRef captures the reference data for an authority snapshot entry.
// Snapshots compact long authority chains from O(total historical enforcement)
// to O(currently active constraints), typically 0-3.
// Evidence_Pointers on snapshots are exempt from the max-10 cap (Decision 51).
type AuthoritySnapshotRef struct {
	TargetRoot       LogPosition   // Root entity being snapshot
	EvidencePointers []LogPosition // Every currently active enforcement entry
	PriorAuthority   LogPosition   // Current Authority_Tip at snapshot time
}
