/*
Package verifier — contest_override.go evaluates whether a pending
operation (key rotation, scope amendment) has been contested, and
whether that contest has been overridden by escrow supermajority.

Given a pending operation position:
 1. Fetch the pending entry → get TargetRoot
 2. Read entity leaf → get AuthorityTip
 3. Walk AuthorityTip chain for contest entries (CosignatureOf == pendingPos)
 4. If no contest → operation unblocked
 5. If contest found → scan for override entries with schema-declared
    supermajority (default ⌈2N/3⌉; simple majority and unanimity
    available via schema override_threshold)
 6. If override_requires_witness → check for independent witness cosig
    BOUND TO THE CONTEST POSITION (BUG-016b)
 7. Return ContestResult with positions and blocked status

BUG-016 FIX (this revision):

	Two call sites previously admitted unrelated evidence as approval:

	  collectEvidenceSigners counted the signer of EVERY entry listed in
	  EvidencePointers, regardless of what that entry was for. Attacker
	  could pad EvidencePointers with unrelated entries from distinct
	  authorities to inflate the override count.

	  hasWitnessCosig returned true for any `CosignatureOf != nil` entry
	  from a non-authority signer, regardless of what the cosignature
	  was for. Attacker could supply a commentary cosignature of any
	  unrelated entry to satisfy the independent-witness requirement.

	Both fixes route through verifier.IsCosignatureOf, which binds
	the cosignature to the specific contest position. The `contestPos`
	parameter is threaded from findOverride through both helpers.

Wave 2 note: the hardcoded ⌈2N/3⌉ threshold moved to the schema's
OverrideThreshold field. Default (missing field / old schemas)
continues to be two-thirds, preserving all pre-Wave-2 behavior.

Consumed by:
  - verifier/key_rotation.go (Tier 3 contest window)
  - Domain verification flows
*/
package verifier

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// ContestResult describes the contest/override status of a pending operation.
type ContestResult struct {
	// OperationBlocked is true if the operation is contested and the
	// contest has NOT been overridden with sufficient supermajority.
	OperationBlocked bool

	// ContestPos is the position of the contest entry, if any.
	ContestPos *types.LogPosition

	// OverridePos is the position of the override entry, if any.
	OverridePos *types.LogPosition

	// Reason describes why the operation is blocked or unblocked.
	Reason string
}

// maxContestScanDepth limits authority chain walk during contest detection.
const maxContestScanDepth = 200

// defaultAuthoritySetSize is the fallback authority-set cardinality used
// when the scope entry cannot be resolved. Three is the protocol's
// canonical minimum scope size and produces a conservative threshold
// under every OverrideThresholdRule (2-of-3 two-thirds, 2-of-3 simple
// majority, 3-of-3 unanimity). This is a structural fallback, not a
// domain assumption.
const defaultAuthoritySetSize = 3

// ─────────────────────────────────────────────────────────────────────
// EvaluateContest
// ─────────────────────────────────────────────────────────────────────

// EvaluateContest checks whether a pending operation has been contested
// and whether any contest has been overridden.
//
// Returns:
//   - OperationBlocked=false, nil positions: no contest exists
//   - OperationBlocked=true, ContestPos set: contested, no valid override
//   - OperationBlocked=false, both set: contested but overridden
func EvaluateContest(
	pendingPos types.LogPosition,
	fetcher EntryFetcher,
	leafReader smt.LeafReader,
	extractor schema.SchemaParameterExtractor,
) (*ContestResult, error) {
	// 1. Fetch pending entry.
	pendingMeta, err := fetcher.Fetch(pendingPos)
	if err != nil || pendingMeta == nil {
		return nil, fmt.Errorf("verifier/contest: pending entry not found at %s", pendingPos)
	}
	pendingEntry, err := envelope.Deserialize(pendingMeta.CanonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("verifier/contest: deserialize pending: %w", err)
	}

	// 2. Must have a TargetRoot (non-commentary operations).
	if pendingEntry.Header.TargetRoot == nil {
		return &ContestResult{
			OperationBlocked: false,
			Reason:           "no target root (commentary or non-targeting entry)",
		}, nil
	}
	targetRoot := *pendingEntry.Header.TargetRoot

	// 3. Get entity leaf.
	leafKey := smt.DeriveKey(targetRoot)
	leaf, err := leafReader.Get(leafKey)
	if err != nil || leaf == nil {
		return &ContestResult{
			OperationBlocked: false,
			Reason:           "target entity leaf not found",
		}, nil
	}

	// 4. Walk authority chain looking for contest entries.
	contestPos, contestEntry := findContest(leaf.AuthorityTip, pendingPos, fetcher)
	if contestPos == nil {
		return &ContestResult{
			OperationBlocked: false,
			Reason:           "no contest found",
		}, nil
	}

	// 5. Contest found — resolve schema-declared override policy.
	var threshold types.OverrideThresholdRule // zero = ThresholdTwoThirdsMajority
	requiresWitness := false
	if extractor != nil && pendingEntry.Header.SchemaRef != nil {
		if params := fetchSchemaParams(*pendingEntry.Header.SchemaRef, fetcher, extractor); params != nil {
			threshold = params.OverrideThreshold
			requiresWitness = params.OverrideRequiresIndependentWitness
		}
	}

	// Determine N from the scope entity's AuthoritySet size.
	authoritySetSize := getAuthoritySetSize(pendingEntry, fetcher)
	if authoritySetSize == 0 {
		authoritySetSize = defaultAuthoritySetSize
	}
	requiredOverride := threshold.RequiredApprovals(authoritySetSize)

	// Extract authority set members for witness independence check.
	authorityMembers := getAuthoritySetMembers(pendingEntry, fetcher)

	// Scan for override: entries after contest with sufficient evidence.
	overridePos, overrideValid := findOverride(
		leaf.AuthorityTip, *contestPos, pendingPos, fetcher,
		requiredOverride, requiresWitness, contestEntry, authorityMembers,
	)

	if overrideValid && overridePos != nil {
		return &ContestResult{
			OperationBlocked: false,
			ContestPos:       contestPos,
			OverridePos:      overridePos,
			Reason:           "contest overridden by supermajority",
		}, nil
	}

	return &ContestResult{
		OperationBlocked: true,
		ContestPos:       contestPos,
		Reason:           "contested, no valid override",
	}, nil
}

// fetchSchemaParams resolves a schema reference to SchemaParameters.
// Returns nil if any step of the resolution fails.
func fetchSchemaParams(
	ref types.LogPosition,
	fetcher EntryFetcher,
	extractor schema.SchemaParameterExtractor,
) *types.SchemaParameters {
	schemaMeta, err := fetcher.Fetch(ref)
	if err != nil || schemaMeta == nil {
		return nil
	}
	schemaEntry, err := envelope.Deserialize(schemaMeta.CanonicalBytes)
	if err != nil {
		return nil
	}
	params, err := extractor.Extract(schemaEntry)
	if err != nil {
		return nil
	}
	return params
}

// findContest walks the authority chain backward from tip looking for
// an entry that is a cosignature of the pending operation.
//
// Uses IsCosignatureOf for SDK-wide consistency. This site was already
// semantically correct (CosignatureOf.Equal was checked inline), but
// routing through the helper eliminates the raw-check pattern and
// satisfies the AST linter.
func findContest(
	tip types.LogPosition,
	pendingPos types.LogPosition,
	fetcher EntryFetcher,
) (*types.LogPosition, *envelope.Entry) {
	current := tip
	visited := make(map[types.LogPosition]bool)

	for depth := 0; depth < maxContestScanDepth; depth++ {
		if visited[current] {
			break
		}
		visited[current] = true

		meta, err := fetcher.Fetch(current)
		if err != nil || meta == nil {
			break
		}
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			break
		}

		// Check if this entry contests the pending operation.
		if IsCosignatureOf(entry, pendingPos) {
			pos := current
			return &pos, entry
		}

		// Follow PriorAuthority chain.
		if entry.Header.PriorAuthority == nil {
			break
		}
		current = *entry.Header.PriorAuthority
	}
	return nil, nil
}

// findOverride scans the authority chain for an override entry that:
// - References the contest position in EvidencePointers
// - Has enough distinct signers bound to the contest (>= requiredOverride)
// - Has a witness cosignature bound to the contest, if required
//
// BUG-016 fix: contestPos is threaded through collectEvidenceSigners
// and hasWitnessCosig so both can bind their checks to the specific
// contest being overridden.
func findOverride(
	tip types.LogPosition,
	contestPos types.LogPosition,
	pendingPos types.LogPosition,
	fetcher EntryFetcher,
	requiredOverride int,
	requiresWitness bool,
	contestEntry *envelope.Entry,
	authorityMembers map[string]bool,
) (*types.LogPosition, bool) {
	current := tip
	visited := make(map[types.LogPosition]bool)

	for depth := 0; depth < maxContestScanDepth; depth++ {
		if visited[current] {
			break
		}
		visited[current] = true

		meta, err := fetcher.Fetch(current)
		if err != nil || meta == nil {
			break
		}
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			break
		}

		// Check if this entry is an override: references contest in evidence.
		if referencesPosition(entry.Header.EvidencePointers, contestPos) {
			// Count distinct signers from evidence entries.
			// BUG-016a: only cosignatures bound to contestPos contribute.
			signers := collectEvidenceSigners(entry.Header.EvidencePointers, fetcher, contestPos)
			// Include the override entry's own signer.
			signers[entry.Header.SignerDID] = true

			if len(signers) >= requiredOverride {
				if requiresWitness {
					// BUG-016b: witness cosig must be bound to contestPos.
					if hasWitnessCosig(entry.Header.EvidencePointers, fetcher, authorityMembers, contestPos) {
						pos := current
						return &pos, true
					}
					// Not enough with witness requirement.
				} else {
					pos := current
					return &pos, true
				}
			}
		}

		if entry.Header.PriorAuthority == nil {
			break
		}
		current = *entry.Header.PriorAuthority
	}
	return nil, false
}

// referencesPosition checks if any position in the slice equals target.
func referencesPosition(pointers []types.LogPosition, target types.LogPosition) bool {
	for _, p := range pointers {
		if p.Equal(target) {
			return true
		}
	}
	return false
}

// collectEvidenceSigners returns the distinct signer DIDs of entries
// that are cosignatures of the contest. Entries listed as evidence
// but not actually cosigning the contest are ignored.
//
// # BUG-016a FIX
//
// Previously this function collected the signer of EVERY entry at each
// evidence pointer, regardless of what that entry was for. An attacker
// could pad EvidencePointers with unrelated entries from distinct
// authorities to trivially satisfy the override threshold.
//
// Now routes through IsCosignatureOf(entry, contestPos) — only entries
// that explicitly cosign the contest contribute their signer. The
// override entry's own signer is added by the caller (findOverride),
// not here.
func collectEvidenceSigners(
	pointers []types.LogPosition,
	fetcher EntryFetcher,
	contestPos types.LogPosition,
) map[string]bool {
	signers := make(map[string]bool)
	for _, ptr := range pointers {
		meta, err := fetcher.Fetch(ptr)
		if err != nil || meta == nil {
			continue
		}
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			continue
		}
		// BUG-016a fix: require the entry to be a cosignature of the
		// contest. Entries listed as evidence but not cosigning the
		// contest do not count toward the override threshold.
		if !IsCosignatureOf(entry, contestPos) {
			continue
		}
		signers[entry.Header.SignerDID] = true
	}
	return signers
}

// hasWitnessCosig reports whether any evidence entry is an independent
// witness cosignature of the contest. Independent means the signer is
// not a member of the authority set.
//
// # BUG-016b FIX
//
// Previously this function returned true for any entry with a non-nil
// CosignatureOf and a non-authority signer, regardless of what that
// cosignature was for. An attacker could supply a commentary
// cosignature of any unrelated entry to satisfy the witness
// requirement.
//
// Now routes through IsCosignatureOf(entry, contestPos) — only
// cosignatures that explicitly reference the contest count as witness
// evidence. The independence check (signer not in authority set) is
// preserved.
func hasWitnessCosig(
	pointers []types.LogPosition,
	fetcher EntryFetcher,
	authorityMembers map[string]bool,
	contestPos types.LogPosition,
) bool {
	for _, ptr := range pointers {
		meta, err := fetcher.Fetch(ptr)
		if err != nil || meta == nil {
			continue
		}
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			continue
		}
		// BUG-016b fix: require binding to the contest position.
		// Previously accepted any `CosignatureOf != nil` from a
		// non-authority signer, ignoring what the cosignature was for.
		if !IsCosignatureOf(entry, contestPos) {
			continue
		}
		if authorityMembers[entry.Header.SignerDID] {
			continue // not independent
		}
		return true
	}
	return false
}

// getAuthoritySetSize reads the AuthoritySet size from the scope entity
// referenced by the pending entry.
func getAuthoritySetSize(pendingEntry *envelope.Entry, fetcher EntryFetcher) int {
	sp := pendingEntry.Header.ScopePointer
	if sp == nil {
		return 0
	}
	meta, err := fetcher.Fetch(*sp)
	if err != nil || meta == nil {
		return 0
	}
	entry, err := envelope.Deserialize(meta.CanonicalBytes)
	if err != nil {
		return 0
	}
	return entry.Header.AuthoritySetSize()
}

// getAuthoritySetMembers reads the AuthoritySet members from the scope
// entity referenced by the pending entry. Returns a set of DID strings.
func getAuthoritySetMembers(pendingEntry *envelope.Entry, fetcher EntryFetcher) map[string]bool {
	members := make(map[string]bool)
	sp := pendingEntry.Header.ScopePointer
	if sp == nil {
		return members
	}
	meta, err := fetcher.Fetch(*sp)
	if err != nil || meta == nil {
		return members
	}
	entry, err := envelope.Deserialize(meta.CanonicalBytes)
	if err != nil {
		return members
	}
	for did := range entry.Header.AuthoritySet {
		members[did] = true
	}
	return members
}
