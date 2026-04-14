/*
Package verifier — contest_override.go evaluates whether a pending
operation (key rotation, scope amendment) has been contested, and
whether that contest has been overridden by escrow supermajority.

Given a pending operation position:
 1. Fetch the pending entry → get TargetRoot
 2. Read entity leaf → get AuthorityTip
 3. Walk AuthorityTip chain for contest entries (CosignatureOf == pendingPos)
 4. If no contest → operation unblocked
 5. If contest found → scan for override entries with ⌈2N/3⌉ supermajority
 6. If override_requires_witness → check for independent witness cosig
 7. Return ContestResult with positions and blocked status

Consumed by:
  - verifier/key_rotation.go (Tier 3 contest window)
  - Domain verification flows
*/
package verifier

import (
	"fmt"
	"math"

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

	// 5. Contest found — check for override.
	// Determine N from the scope entity's AuthoritySet size.
	authoritySetSize := getAuthoritySetSize(pendingEntry, fetcher)
	if authoritySetSize == 0 {
		authoritySetSize = 3 // Safe default if scope not found.
	}
	requiredOverride := int(math.Ceil(2.0 * float64(authoritySetSize) / 3.0))

	// Check if override_requires_witness.
	requiresWitness := false
	if extractor != nil && pendingEntry.Header.SchemaRef != nil {
		schemaMeta, fetchErr := fetcher.Fetch(*pendingEntry.Header.SchemaRef)
		if fetchErr == nil && schemaMeta != nil {
			schemaEntry, desErr := envelope.Deserialize(schemaMeta.CanonicalBytes)
			if desErr == nil {
				params, extErr := extractor.Extract(schemaEntry)
				if extErr == nil && params != nil {
					requiresWitness = params.OverrideRequiresIndependentWitness
				}
			}
		}
	}

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

// findContest walks the authority chain backward from tip looking for
// an entry with CosignatureOf == pendingPos.
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
		if entry.Header.CosignatureOf != nil && entry.Header.CosignatureOf.Equal(pendingPos) {
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
// - Has enough distinct signers (>= requiredOverride)
// - Has a witness cosignature if required
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
			signers := collectEvidenceSigners(entry.Header.EvidencePointers, fetcher)
			// Include the override entry's own signer.
			signers[entry.Header.SignerDID] = true

			if len(signers) >= requiredOverride {
				if requiresWitness {
					if hasWitnessCosig(entry.Header.EvidencePointers, fetcher, authorityMembers) {
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

// collectEvidenceSigners fetches entries at evidence positions and
// collects distinct signer DIDs.
func collectEvidenceSigners(pointers []types.LogPosition, fetcher EntryFetcher) map[string]bool {
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
		signers[entry.Header.SignerDID] = true
	}
	return signers
}

// hasWitnessCosig checks if any evidence entry is a witness cosignature
// (signer not in the authority set → independent witness).
func hasWitnessCosig(pointers []types.LogPosition, fetcher EntryFetcher, authorityMembers map[string]bool) bool {
	for _, ptr := range pointers {
		meta, err := fetcher.Fetch(ptr)
		if err != nil || meta == nil {
			continue
		}
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			continue
		}
		// A witness cosignature is from a signer NOT in the authority set
		// AND the entry has CosignatureOf set, marking it as an independent witness.
		if entry.Header.CosignatureOf != nil && !authorityMembers[entry.Header.SignerDID] {
			return true
		}
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
