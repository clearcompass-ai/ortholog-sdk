package types

// SMTDerivationCommitment captures the state transition for a batch of entries.
// Published as a commentary entry on the log (zero SMT impact).
// Enables O(batch) incremental verification and O(1) fraud proofs.
type SMTDerivationCommitment struct {
	LogRangeStart LogPosition   // First entry in the batch
	LogRangeEnd   LogPosition   // Last entry in the batch
	PriorSMTRoot  [32]byte      // SMT root before this batch
	PostSMTRoot   [32]byte      // SMT root after this batch
	Mutations     []LeafMutation // Ordered list of leaf changes
	MutationCount uint32         // len(Mutations), explicit for serialization
}

// LeafMutation records a single leaf state change within a batch.
type LeafMutation struct {
	LeafKey         [32]byte    // SHA-256(log_position) of the root entity
	OldOriginTip    LogPosition // Origin_Tip before this mutation
	NewOriginTip    LogPosition // Origin_Tip after this mutation
	OldAuthorityTip LogPosition // Authority_Tip before this mutation
	NewAuthorityTip LogPosition // Authority_Tip after this mutation
}
