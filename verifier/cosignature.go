/*
FILE PATH:

	verifier/cosignature.go

DESCRIPTION:

	Single source of truth for cosignature-to-position binding checks.
	All code in the SDK that consumes an entry claiming to be a cosignature
	must route through IsCosignatureOf — never check `CosignatureOf != nil`
	raw — so that every consumer binds the reference to the specific
	position it is approving.

	THE PATTERN THIS CLOSES
	───────────────────────
	Multiple sites in the SDK previously checked:

	    if entry.Header.CosignatureOf != nil { ... count this as approval }

	This pattern is UNSAFE. It accepts any commentary-style cosignature
	regardless of what that cosignature is for. An attacker collecting
	cosignatures on unrelated entries (old proposals, witness cosigs from
	other logs, routine commentary) can present those cosignatures as
	"approval" of an entirely different pending operation.

	ORTHO-BUG-009, ORTHO-BUG-015, and ORTHO-BUG-016 are all instances of
	this pattern. The fix is the bound check performed by this helper.

	SECURITY INVARIANT ENFORCED
	───────────────────────────
	IsCosignatureOf(entry, expectedPos) returns true iff:
	  1. entry is non-nil,
	  2. entry.Header.CosignatureOf is non-nil,
	  3. entry.Header.CosignatureOf.Equal(expectedPos).

	All three must hold. Any caller using this helper is guaranteed that
	a true result means the cosignature is cryptographically bound to the
	specific operation under evaluation.

	ENFORCEMENT
	───────────
	cmd/lint-cosignature-binding enforces this pattern at CI time by
	AST-scanning for raw `CosignatureOf != nil` and `CosignatureOf == nil`
	expressions. This file is whitelisted in the linter as the canonical
	home of such checks. Any other file failing the linter must either
	route through IsCosignatureOf or document via line-level directive
	why a raw check is semantically correct (e.g., validating absence,
	not presence).
*/
package verifier

import (
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// IsCosignatureOf reports whether entry is a cosignature that references
// expectedPos. It is the SDK's canonical predicate for binding a
// cosignature entry to the specific log position it approves.
//
// Returns true iff:
//   - entry is non-nil,
//   - entry.Header.CosignatureOf is non-nil,
//   - entry.Header.CosignatureOf.Equal(expectedPos) is true.
//
// Callers should use this helper everywhere a cosignature's relevance
// must be verified before counting it as approval. Never write raw
// `entry.Header.CosignatureOf != nil` checks at consumption sites —
// those are unsafe and the AST linter will reject them.
//
// Thread-safe: this function reads only the fields of its inputs and
// allocates nothing. Safe to call concurrently from any goroutine.
//
// Examples:
//
//	// Counting valid cosignatures for a pending operation:
//	count := 0
//	for _, meta := range cosignatures {
//	    entry, err := envelope.Deserialize(meta.CanonicalBytes)
//	    if err != nil {
//	        continue
//	    }
//	    if !IsCosignatureOf(entry, pending.Position) {
//	        continue // not for this operation
//	    }
//	    count++
//	}
//
//	// Arbitration: witness must cosign the specific recovery request:
//	witnessEntry, err := envelope.Deserialize(p.WitnessCosignature.CanonicalBytes)
//	if err != nil || !IsCosignatureOf(witnessEntry, p.RecoveryRequestPos) {
//	    return &ArbitrationResult{Reason: "witness cosignature does not reference request"}, nil
//	}
func IsCosignatureOf(entry *envelope.Entry, expectedPos types.LogPosition) bool {
	if entry == nil {
		return false
	}
	if entry.Header.CosignatureOf == nil {
		return false
	}
	return entry.Header.CosignatureOf.Equal(expectedPos)
}
