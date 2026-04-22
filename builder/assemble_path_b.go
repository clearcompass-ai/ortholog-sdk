package builder

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

var (
	ErrChainTooDeep       = fmt.Errorf("builder/path_b: delegation chain exceeds max depth %d", envelope.MaxDelegationPointers)
	ErrChainDisconnected  = fmt.Errorf("builder/path_b: delegation chain is disconnected")
	ErrChainCycle         = fmt.Errorf("builder/path_b: cycle detected in delegation chain")
	ErrDelegationNotLive  = fmt.Errorf("builder/path_b: delegation is not live (revoked or amended)")
	ErrDelegationNotFound = fmt.Errorf("builder/path_b: delegation entry not found")
	ErrNoDelegateDID      = fmt.Errorf("builder/path_b: delegation entry missing Delegate_DID")
	ErrRootNotFound       = fmt.Errorf("builder/path_b: root entity entry not found")
)

// DelegationHop describes one hop in the assembled delegation chain.
// Defined in builder (not verifier) to avoid circular imports.
type DelegationHop struct {
	Position    types.LogPosition
	SignerDID   string
	DelegateDID string
	IsLive      bool
}

// AssemblePathBParams configures delegation chain assembly.
type AssemblePathBParams struct {
	DelegateDID        string              // Action signer's DID.
	TargetRoot         types.LogPosition   // Root entity being targeted.
	LeafReader         smt.LeafReader      // SMT leaf access for liveness checks.
	Fetcher            types.EntryFetcher        // Positional entry lookup.
	MaxDepth           int                 // 0 = default (MaxDelegationPointers).
	CandidatePositions []types.LogPosition // Delegation positions the caller knows about.
}

// PathBAssembly is the result of successful delegation chain assembly.
type PathBAssembly struct {
	DelegationPointers []types.LogPosition // Ordered for BuildPathBEntry.
	Hops               []DelegationHop     // Full chain details for inspection.
}

// AssemblePathB validates, filters, and orders delegation positions the
// caller provides. It connects DelegateDID back to the root entity's signer
// through delegation entries at CandidatePositions.
func AssemblePathB(params AssemblePathBParams) (*PathBAssembly, error) {
	if len(params.CandidatePositions) == 0 {
		return nil, ErrEmptyDelegationChain
	}
	maxDepth := params.MaxDepth
	if maxDepth <= 0 {
		maxDepth = envelope.MaxDelegationPointers
	}
	if len(params.CandidatePositions) > maxDepth {
		return nil, ErrChainTooDeep
	}

	// Resolve root entity signer.
	rootMeta, err := params.Fetcher.Fetch(params.TargetRoot)
	if err != nil || rootMeta == nil {
		return nil, fmt.Errorf("%w: %s", ErrRootNotFound, params.TargetRoot)
	}
	rootEntry, err := envelope.Deserialize(rootMeta.CanonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: deserialize root: %v", ErrRootNotFound, err)
	}
	rootSignerDID := rootEntry.Header.SignerDID

	// Load all candidate delegation entries.
	type delegInfo struct {
		pos         types.LogPosition
		signerDID   string
		delegateDID string
		isLive      bool
		used        bool
	}
	candidates := make([]delegInfo, 0, len(params.CandidatePositions))
	for _, pos := range params.CandidatePositions {
		meta, err := params.Fetcher.Fetch(pos)
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

		leafKey := smt.DeriveKey(pos)
		leaf, leafErr := params.LeafReader.Get(leafKey)
		live := leafErr == nil && leaf != nil && leaf.OriginTip.Equal(pos)

		candidates = append(candidates, delegInfo{
			pos:         pos,
			signerDID:   entry.Header.SignerDID,
			delegateDID: *entry.Header.DelegateDID,
			isLive:      live,
		})
	}

	// Build chain: walk from DelegateDID toward rootSignerDID.
	var chain []delegInfo
	currentExpected := params.DelegateDID
	visited := make(map[string]bool)

	for depth := 0; depth < maxDepth; depth++ {
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

				if candidates[i].signerDID == rootSignerDID {
					result := &PathBAssembly{
						DelegationPointers: make([]types.LogPosition, len(chain)),
						Hops:               make([]DelegationHop, len(chain)),
					}
					for j, c := range chain {
						result.DelegationPointers[j] = c.pos
						result.Hops[j] = DelegationHop{
							Position:    c.pos,
							SignerDID:   c.signerDID,
							DelegateDID: c.delegateDID,
							IsLive:      c.isLive,
						}
					}
					return result, nil
				}
				currentExpected = candidates[i].signerDID
				break
			}
		}
		if !found {
			break
		}
	}

	return nil, fmt.Errorf("%w: could not connect %s to %s",
		ErrChainDisconnected, params.DelegateDID, rootSignerDID)
}

// ValidateChainParams configures post-assembly liveness validation.
type ValidateChainParams struct {
	DelegationPointers []types.LogPosition
	LeafReader         smt.LeafReader
	Fetcher            types.EntryFetcher
}

// ChainLivenessResult is the output of ValidateChainLiveness.
type ChainLivenessResult struct {
	AllLive    bool
	FirstDead  *types.LogPosition
	DeadReason string
}

// ValidateChainLiveness checks that every delegation pointer is still live.
// Called after AssemblePathB to ensure the chain will succeed at processing time.
func ValidateChainLiveness(params ValidateChainParams) (*ChainLivenessResult, error) {
	for _, pos := range params.DelegationPointers {
		leafKey := smt.DeriveKey(pos)
		leaf, err := params.LeafReader.Get(leafKey)
		if err != nil || leaf == nil {
			p := pos
			return &ChainLivenessResult{
				AllLive:    false,
				FirstDead:  &p,
				DeadReason: "leaf not found in SMT",
			}, nil
		}
		if !leaf.OriginTip.Equal(pos) {
			p := pos
			return &ChainLivenessResult{
				AllLive:    false,
				FirstDead:  &p,
				DeadReason: fmt.Sprintf("OriginTip %s != delegation position %s", leaf.OriginTip, pos),
			}, nil
		}
	}
	return &ChainLivenessResult{AllLive: true}, nil
}
