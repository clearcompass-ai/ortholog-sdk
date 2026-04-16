/*
Package builder — path_compression.go provides leaf-mutation primitives
used by Path A / Path B / Path C processors, structured as a
compute-then-apply pipeline.

Two layers:

	Compute primitives (computeOriginTipUpdate, computeAuthorityTipUpdate,
	computeIntermediateOriginTip, computeIntermediateAuthorityTip):
	    Read-only functions that validate invariants (monotonicity,
	    locality, existence) and return the mutated leaf struct without
	    touching the SMT or DeltaWindowBuffer.

	Apply primitive (applyLeafUpdates):
	    Writes a set of mutations to the SMT in sequence and records
	    DeltaWindowBuffer entries only after successful commits.

The compute/apply split exists to eliminate the partial-mutation bug
class: if any compute step fails, zero SMT writes have happened.
All validation occurs before any state is mutated.

Invariants enforced:
  - Monotonicity: tips only advance (same-log regression rejected).
  - Locality (Decision 47): intermediates must be on the local log.
  - Existence: intermediates must exist (no silent no-ops).
*/
package builder

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

var (
	// ErrTipRegression — an update tried to move a tip to an older
	// position on the same log. Tips may only advance.
	ErrTipRegression = errors.New("builder/path: tip regression rejected")

	// ErrIntermediateNotFound — TargetIntermediate references a leaf
	// that does not exist in the SMT.
	ErrIntermediateNotFound = errors.New("builder/path: TargetIntermediate leaf not found")

	// ErrIntermediateForeign — TargetIntermediate references a foreign
	// log, violating Decision 47 locality.
	ErrIntermediateForeign = errors.New("builder/path: TargetIntermediate on foreign log")
)

// ─────────────────────────────────────────────────────────────────────
// Update — a staged leaf mutation
// ─────────────────────────────────────────────────────────────────────

// leafUpdate bundles a leaf's target key with the post-mutation leaf
// struct. A batch of leafUpdates collected from compute* calls can be
// applied to the SMT safely by applyLeafUpdates.
//
// The recordsBuffer flag marks whether the DeltaWindowBuffer should
// record this mutation after a successful SMT commit. Only AuthorityTip
// updates (and intermediate AuthorityTip updates in the Path C
// enforcement branch) set this flag.
type leafUpdate struct {
	key           [32]byte
	leaf          types.SMTLeaf
	bufferPos     types.LogPosition
	recordsBuffer bool
}

// ─────────────────────────────────────────────────────────────────────
// Compute primitives — read-only, return mutations without applying
// ─────────────────────────────────────────────────────────────────────

// computeOriginTipUpdate validates and computes the OriginTip update
// for a leaf. Returns the mutated leaf; does not write.
func computeOriginTipUpdate(
	leafKey [32]byte,
	leaf *types.SMTLeaf,
	newTip types.LogPosition,
) (leafUpdate, error) {
	if err := assertMonotonic(leaf.OriginTip, newTip, "OriginTip"); err != nil {
		return leafUpdate{}, err
	}
	updated := *leaf
	updated.OriginTip = newTip
	return leafUpdate{key: leafKey, leaf: updated}, nil
}

// computeAuthorityTipUpdate validates and computes the AuthorityTip update
// for a leaf. Returns the mutated leaf and flags the DeltaWindowBuffer
// for recording on successful apply.
func computeAuthorityTipUpdate(
	leafKey [32]byte,
	leaf *types.SMTLeaf,
	newTip types.LogPosition,
) (leafUpdate, error) {
	if err := assertMonotonic(leaf.AuthorityTip, newTip, "AuthorityTip"); err != nil {
		return leafUpdate{}, err
	}
	updated := *leaf
	updated.AuthorityTip = newTip
	return leafUpdate{
		key:           leafKey,
		leaf:          updated,
		bufferPos:     newTip,
		recordsBuffer: true,
	}, nil
}

// computeIntermediateOriginTip validates locality, existence, and
// monotonicity for an intermediate, then computes the OriginTip update.
// Does not write.
func computeIntermediateOriginTip(
	tree *smt.Tree,
	intermediate, newTip types.LogPosition,
	localLogDID string,
) (leafUpdate, error) {
	if intermediate.LogDID != localLogDID {
		return leafUpdate{}, fmt.Errorf("%w: %s", ErrIntermediateForeign, intermediate)
	}
	intKey := smt.DeriveKey(intermediate)
	intLeaf, err := tree.GetLeaf(intKey)
	if err != nil {
		return leafUpdate{}, fmt.Errorf("builder/path: read intermediate leaf: %w", err)
	}
	if intLeaf == nil {
		return leafUpdate{}, fmt.Errorf("%w: %s", ErrIntermediateNotFound, intermediate)
	}
	return computeOriginTipUpdate(intKey, intLeaf, newTip)
}

// computeIntermediateAuthorityTip — same as above but for AuthorityTip.
// Flags the buffer for recording on successful apply.
func computeIntermediateAuthorityTip(
	tree *smt.Tree,
	intermediate, newTip types.LogPosition,
	localLogDID string,
) (leafUpdate, error) {
	if intermediate.LogDID != localLogDID {
		return leafUpdate{}, fmt.Errorf("%w: %s", ErrIntermediateForeign, intermediate)
	}
	intKey := smt.DeriveKey(intermediate)
	intLeaf, err := tree.GetLeaf(intKey)
	if err != nil {
		return leafUpdate{}, fmt.Errorf("builder/path: read intermediate leaf: %w", err)
	}
	if intLeaf == nil {
		return leafUpdate{}, fmt.Errorf("%w: %s", ErrIntermediateNotFound, intermediate)
	}
	return computeAuthorityTipUpdate(intKey, intLeaf, newTip)
}

// ─────────────────────────────────────────────────────────────────────
// Apply primitive — writes staged updates to SMT and buffer
// ─────────────────────────────────────────────────────────────────────

// applyLeafUpdates commits staged leaf updates to the SMT. DeltaWindowBuffer
// entries are recorded only after successful SetLeaf calls so failed writes
// never leave phantom buffer records.
func applyLeafUpdates(
	tree *smt.Tree,
	buffer *DeltaWindowBuffer,
	updates []leafUpdate,
) error {
	for i, u := range updates {
		if err := tree.SetLeaf(u.key, u.leaf); err != nil {
			return fmt.Errorf("builder/path: apply update %d of %d: %w",
				i+1, len(updates), err)
		}
		if u.recordsBuffer && buffer != nil {
			buffer.Record(u.key, u.bufferPos)
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// assertMonotonic verifies that newTip is a valid forward advance from
// currentTip. The rules:
//
//   - If currentTip is the zero value (fresh leaf), any newTip is OK.
//   - If currentTip and newTip share a LogDID, newTip.Sequence must
//     strictly exceed currentTip.Sequence.
//   - If the LogDIDs differ, the transition is a cross-log move
//     (relay entry); no sequence ordering applies.
func assertMonotonic(currentTip, newTip types.LogPosition, fieldName string) error {
	if currentTip.LogDID == "" && currentTip.Sequence == 0 {
		return nil // fresh leaf
	}
	if currentTip.LogDID != newTip.LogDID {
		return nil // cross-log transition — sequence not comparable
	}
	if newTip.Sequence <= currentTip.Sequence {
		return fmt.Errorf("%w: %s %s → %s",
			ErrTipRegression, fieldName, currentTip, newTip)
	}
	return nil
}
