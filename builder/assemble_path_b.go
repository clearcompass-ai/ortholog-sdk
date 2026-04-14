/*
Package builder — assemble_path_b.go assembles delegation chains for
Path B entries.

AssemblePathB walks from a delegate DID backward through delegation
entries to the root entity signer, collecting the ordered
DelegationPointers slice required by BuildPathBEntry.

The delegation chain connects:
  delegate (action signer) ← delegation₁ ← delegation₂ ← ... ← root signer

Each delegation entry has:
  SignerDID   = who granted the delegation (upstream)
  DelegateDID = who received it (downstream, toward the action signer)

The chain is validated for:
  - Maximum depth (3 hops per protocol)
  - Liveness (each delegation leaf's OriginTip == delegation position)
  - Connectivity (each hop's SignerDID matches the next hop's DelegateDID)
  - Cycle detection (no DID appears twice in the chain)

Consumed by domain applications that need to build Path B entries
programmatically (e.g., clerk filing via delegated authority from judge).
*/
package builder

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

var (
	ErrChainTooDeep      = fmt.Errorf("builder/path_b: delegation chain exceeds max depth %d", envelope.MaxDelegationPointers)
	ErrChainDisconnected = fmt.Errorf("builder/path_b: delegation chain is disconnected")
	ErrChainCycle        = fmt.Errorf("builder/path_b: cycle detected in delegation chain")
	ErrDelegationNotLive = fmt.Errorf("builder/path_b: delegation is not live (revoked or amended)")
	ErrDelegationNotFound = fmt.Errorf("builder/path_b: delegation entry not found")
	ErrNoDelegateDID     = fmt.Errorf("builder/path_b: delegation entry missing Delegate_DID")
)

// ─────────────────────────────────────────────────────────────────────
// AssemblePathB
// ─────────────────────────────────────────────────────────────────────

// DelegationLink describes one hop in the assembled delegation chain.
type DelegationLink struct {
	Position    types.LogPosition // LogPosition of the delegation entry.
	SignerDID   string            // Who created the delegation (grantor).
	DelegateDID string            // Who received the delegation (grantee).
	IsLive      bool              // OriginTip == Position (not revoked).
}

// AssemblePathBResult is the output of delegation chain assembly.
type AssemblePathBResult struct {
	// DelegationPointers is the ordered slice for BuildPathBEntry.
	// Order: closest to action signer first, root signer's delegation last.
	DelegationPointers []types.LogPosition

	// Links contains the full chain details for inspection.
	Links []DelegationLink

	// RootSignerDID is the DID at the top of the chain (the root
	// entity's signer that the chain connects to).
	RootSignerDID string
}

// AssemblePathB resolves and validates a delegation chain from a set
// of candidate delegation positions. The chain must connect the
// actionSignerDID (the delegate performing the action) back to the
// rootSignerDID (the signer of the target root entity).
//
// candidatePositions: positions of delegation entries to consider.
//   The function selects and orders the relevant subset.
//
// actionSignerDID: the DID that will sign the Path B entry.
//
// rootSignerDID: the SignerDID of the target root entity (the chain
//   must terminate at a delegation whose SignerDID == rootSignerDID).
//
// fetcher: retrieves delegation entries by position.
//
// leafReader: checks delegation liveness (OriginTip == position).
//
// Returns the assembled chain or an error if the chain is invalid.
func AssemblePathB(
	candidatePositions []types.LogPosition,
	actionSignerDID string,
	rootSignerDID string,
	fetcher EntryFetcher,
	leafReader smt.LeafReader,
) (*AssemblePathBResult, error) {
	if len(candidatePositions) == 0 {
		return nil, ErrEmptyDelegationChain
	}
	if len(candidatePositions) > envelope.MaxDelegationPointers {
		return nil, ErrChainTooDeep
	}

	// Load all candidate delegation entries.
	type delegInfo struct {
		pos         types.LogPosition
		signerDID   string
		delegateDID string
		isLive      bool
		used        bool
	}

	candidates := make([]delegInfo, 0, len(candidatePositions))
	for _, pos := range candidatePositions {
		meta, err := fetcher.Fetch(pos)
		if err != nil || meta == nil {
			return nil, fmt.Errorf("%w: %s", ErrDelegationNotFound, pos)
		}
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: deserialize %s: %v", ErrDelegationNotFound, pos, err)
		}
		if entry.Header.DelegateDID == nil {
			return nil, fmt.Errorf("%w: %s", ErrNoDelegateDID, pos)
		}

		// Check liveness.
		leafKey := smt.DeriveKey(pos)
		leaf, leafErr := leafReader.Get(leafKey)
		live := leafErr == nil && leaf != nil && leaf.OriginTip.Equal(pos)

		candidates = append(candidates, delegInfo{
			pos:         pos,
			signerDID:   entry.Header.SignerDID,
			delegateDID: *entry.Header.DelegateDID,
			isLive:      live,
		})
	}

	// Build the chain: start from actionSignerDID, walk toward rootSignerDID.
	// At each step, find the candidate whose DelegateDID == currentExpected.
	var chain []delegInfo
	currentExpected := actionSignerDID
	visited := make(map[string]bool)

	for depth := 0; depth < envelope.MaxDelegationPointers; depth++ {
		if visited[currentExpected] {
			return nil, ErrChainCycle
		}
		visited[currentExpected] = true

		found := false
		for i := range candidates {
			if candidates[i].used {
				continue
			}
			if candidates[i].delegateDID == currentExpected {
				candidates[i].used = true
				chain = append(chain, candidates[i])
				found = true

				// Check if we've reached the root.
				if candidates[i].signerDID == rootSignerDID {
					// Chain complete.
					return buildResult(chain), nil
				}
				currentExpected = candidates[i].signerDID
				break
			}
		}
		if !found {
			break
		}
	}

	// If we get here, the chain didn't connect to rootSignerDID.
	return nil, fmt.Errorf("%w: could not connect %s to %s",
		ErrChainDisconnected, actionSignerDID, rootSignerDID)
}

// buildResult converts the internal chain representation to the public result.
func buildResult(chain []delegInfo) *AssemblePathBResult {
	result := &AssemblePathBResult{
		DelegationPointers: make([]types.LogPosition, len(chain)),
		Links:              make([]DelegationLink, len(chain)),
	}
	for i, d := range chain {
		result.DelegationPointers[i] = d.pos
		result.Links[i] = DelegationLink{
			Position:    d.pos,
			SignerDID:   d.signerDID,
			DelegateDID: d.delegateDID,
			IsLive:      d.isLive,
		}
	}
	if len(chain) > 0 {
		result.RootSignerDID = chain[len(chain)-1].signerDID
	}
	return result
}

// ValidateChainLiveness checks that every delegation in the chain is live.
// Called after AssemblePathB to ensure the chain will succeed at Path B
// processing time. Returns the first non-live link, or nil if all are live.
func ValidateChainLiveness(result *AssemblePathBResult) *DelegationLink {
	for i := range result.Links {
		if !result.Links[i].IsLive {
			return &result.Links[i]
		}
	}
	return nil
}
