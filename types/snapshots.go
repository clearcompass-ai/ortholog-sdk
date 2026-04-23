/*
Package types — snapshots.go declares the descriptor for a Path C
authority snapshot. Authority snapshots are the protocol's light-client
shortcut: a single entry that compresses a range of prior enforcement
actions into an EvidencePointers array, so that an authority-chain
walker can skip reconstruction of intermediate state.

An AuthoritySnapshotRef is the read-side view of a snapshot entry. It
carries only the three positional references the verifier needs to
evaluate the snapshot:

  - TargetRoot:       the entity whose authority state the snapshot
    asserts.
  - PriorAuthority:   the Authority_Tip the snapshot signer observed;
    used for OCC and for the authority-chain walk
    terminator.
  - EvidencePointers: the compressed range of enforcement entries the
    snapshot attests are still in force. For a
    snapshot, this list is exempt from the routine
    MaxEvidencePointers (32) cap.

Shape detection. A header qualifies as a snapshot when
envelope.IsAuthoritySnapshotShape returns true (Path C + TargetRoot +
PriorAuthority). The SDK shape-detects snapshots rather than declaring
them via a dedicated AuthorityPath constant because a snapshot is
structurally a scope-authority enforcement that happens to carry
evidence; treating it as a separate path would fragment the Path C
enforcement lane for no gain.

Constructor placement. The snapshot descriptor lives in package types
(so consumers can hold a snapshot reference without importing envelope),
but the NewAuthoritySnapshotRefFromHeader constructor lives in
core/envelope/subtypes.go. The envelope package already imports types,
so the opposite direction would cycle.

Consumers. Used by verifier/authority_evaluator.go to extract snapshot
metadata during authority-chain walking. Domain callers constructing
snapshot references for off-chain proofs populate this struct directly.
*/
package types

// AuthoritySnapshotRef is the descriptor for a Path C authority snapshot.
// All fields are required; a zero-valued field indicates the source
// entry was not a valid snapshot.
type AuthoritySnapshotRef struct {
	// TargetRoot is the root entity whose authority state the snapshot
	// asserts. Matches envelope.ControlHeader.TargetRoot.
	TargetRoot LogPosition

	// PriorAuthority is the Authority_Tip observed at signing time.
	// Matches envelope.ControlHeader.PriorAuthority. Terminates the
	// authority-chain walk: walkers that reach PriorAuthority replace
	// the remaining walk with EvidencePointers.
	PriorAuthority LogPosition

	// EvidencePointers is the compressed range of enforcement entries
	// the snapshot attests are still in force at signing time. Not
	// subject to the routine 32-pointer cap; snapshots may carry
	// arbitrarily many evidence references.
	EvidencePointers []LogPosition
}

// IsActiveShortcut reports whether the snapshot carries enough evidence
// to serve as an authority-chain shortcut. Snapshots with zero evidence
// pointers are shape-valid (so the envelope writer admits them) but do
// not compress anything; a walker should fall back to hop-by-hop.
func (s *AuthoritySnapshotRef) IsActiveShortcut() bool {
	return s != nil && len(s.EvidencePointers) > 0
}
