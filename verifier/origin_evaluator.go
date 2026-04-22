/*
Package verifier — origin_evaluator.go is the O(1) Origin lane reader.

Takes a leaf key, reads the SMT leaf via LeafReader.Get(key), fetches
the entry at OriginTip via EntryFetcher, and classifies the current
origin state.

States:
  Original  — OriginTip entry has no TargetRoot (IS the root entity entry).
  Amended   — OriginTip advanced to an entry whose TargetRoot resolves to
              this leaf (same entity modified via Path A or scope amendment).
  Revoked   — OriginTip advanced but the tip entry does not target this leaf
              (delegation revoked, entity removed).
  Succeeded — OriginTip advanced to an entry referencing a successor entity
              (schema succession, superseded credential).
  Pending   — Reserved for activation-delay evaluation (requires schema
              parameters + Log_Time).

One hop via path compression: if the tip entry has TargetIntermediate,
the evaluator reports both the root and intermediate positions affected.

Consumed by:
  - verification/case_status.go in the judicial network
  - Domain verification flows that ask "what's the current state?"
*/
package verifier

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// OriginState classifies the current state of an entity's Origin lane.
type OriginState uint8

const (
	// OriginOriginal means the entity is untouched — OriginTip is still the
	// root entity entry (no TargetRoot, no amendment).
	OriginOriginal OriginState = iota

	// OriginAmended means OriginTip advanced to an entry whose TargetRoot
	// resolves to this leaf's key (same entity modified).
	OriginAmended

	// OriginRevoked means OriginTip advanced but the tip entry does not
	// target this leaf (revocation, removal, or the tip entry is missing).
	OriginRevoked

	// OriginSucceeded means the entity has been superseded by a successor.
	// Detected when the tip entry targets a different entity as part of
	// a succession chain.
	OriginSucceeded

	// OriginPending means a change is within the activation delay window.
	// Requires schema parameter evaluation — not determined by this evaluator
	// alone. The caller checks ActivationDelay against Log_Time.
	OriginPending
)

// OriginEvaluation holds the result of origin lane evaluation.
type OriginEvaluation struct {
	// State is the classified origin state.
	State OriginState

	// TipEntry is the deserialized entry at OriginTip. Nil if the entry
	// could not be fetched or deserialized.
	TipEntry *envelope.Entry

	// TipPosition is the OriginTip LogPosition from the SMT leaf.
	TipPosition types.LogPosition

	// IntermediatePosition is set when the tip entry uses path compression
	// (TargetIntermediate is non-nil). Nil otherwise.
	IntermediatePosition *types.LogPosition
}

// Errors.
var (
	ErrLeafNotFound       = errors.New("verifier/origin: leaf not found")
	ErrOriginTipNotFound  = errors.New("verifier/origin: entry at OriginTip not found")
	ErrOriginDeserialize  = errors.New("verifier/origin: failed to deserialize tip entry")
)

// ─────────────────────────────────────────────────────────────────────
// EvaluateOrigin — O(1) origin lane reader
// ─────────────────────────────────────────────────────────────────────

// EvaluateOrigin reads the Origin lane for a given leaf key and classifies
// the current state.
//
// Algorithm (O(1) — exactly one leaf read + one entry fetch):
//  1. Read SMT leaf by key via LeafReader.
//  2. Fetch the entry at leaf.OriginTip via EntryFetcher.
//  3. Classify:
//     a. Entry has no TargetRoot → Original (this IS the root entity).
//     b. Entry has TargetRoot and DeriveKey(*TargetRoot) == leafKey → Amended.
//     c. Entry has TargetRoot but DeriveKey(*TargetRoot) != leafKey → Revoked.
//  4. If tip entry uses path compression (TargetIntermediate), report it.
func EvaluateOrigin(
	leafKey [32]byte,
	leafReader smt.LeafReader,
	fetcher types.EntryFetcher,
) (*OriginEvaluation, error) {
	// Step 1: Read leaf.
	leaf, err := leafReader.Get(leafKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLeafNotFound, err)
	}
	if leaf == nil {
		return nil, ErrLeafNotFound
	}

	eval := &OriginEvaluation{
		TipPosition: leaf.OriginTip,
	}

	// Step 2: Fetch entry at OriginTip.
	tipMeta, err := fetcher.Fetch(leaf.OriginTip)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOriginTipNotFound, err)
	}
	if tipMeta == nil {
		// Tip points to a non-existent entry — the entity was revoked
		// (OriginTip was advanced to a position without a valid entry).
		eval.State = OriginRevoked
		return eval, nil
	}

	// Deserialize the tip entry.
	tipEntry, err := envelope.Deserialize(tipMeta.CanonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOriginDeserialize, err)
	}
	eval.TipEntry = tipEntry

	// Step 3: Classify.
	h := &tipEntry.Header

	if h.TargetRoot == nil {
		// No TargetRoot → this is the root entity entry itself.
		// The entity has never been amended via Path A.
		eval.State = OriginOriginal
		return eval, nil
	}

	// TargetRoot is set → OriginTip was advanced by a Path A or scope amendment.
	// Check if the target resolves to our leaf.
	targetKey := smt.DeriveKey(*h.TargetRoot)

	if targetKey == leafKey {
		// The tip entry targets this entity → amended.
		eval.State = OriginAmended

		// Check for path compression (TargetIntermediate).
		if h.TargetIntermediate != nil {
			eval.IntermediatePosition = h.TargetIntermediate
		}
	} else {
		// The tip entry targets a different entity.
		// This happens when OriginTip was advanced to a foreign position
		// (revocation or succession).
		eval.State = OriginRevoked
	}

	return eval, nil
}
