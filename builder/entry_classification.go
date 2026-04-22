package builder

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// ClassifyParams configures read-only entry classification.
//
// SchemaResolver is optional: when nil, the classifier defaults to strict
// OCC (Decision 37), matching ProcessBatch's behaviour when its resolver is
// nil. Bridges that need to predict Path C admission for commutative
// schemas must supply the same resolver the live builder will use — any
// divergence between the two resolvers reintroduces ORTHO-BUG-004.
type ClassifyParams struct {
	Entry          *envelope.Entry
	Position       types.LogPosition // Entry's own position (for context).
	LeafReader     smt.LeafReader
	Fetcher        types.EntryFetcher
	LocalLogDID    string
	SchemaResolver SchemaResolver
}

// Classification is the result of ClassifyEntry.
type Classification struct {
	Path    PathResult
	Reason  string
	Details ClassificationDetails
}

// ClassificationDetails provides additional metadata about the classification.
type ClassificationDetails struct {
	TargetLeafKey    *[32]byte // SMT key for the target entity (nil for commentary).
	DelegationDepth  int       // Number of hops in delegation chain (Path B only).
	AuthoritySetSize int       // Size of scope authority set (Path C only).
	IsCommentary     bool      // True for zero-SMT-impact entries.
	OCCNoteReadOnly  bool      // True when commutative schema accepted a Prior_Authority mismatch provisionally; runtime Δ-window check still required.
}

// ─────────────────────────────────────────────────────────────────────
// ClassifyEntry
// ─────────────────────────────────────────────────────────────────────

// ClassifyEntry determines what path an entry would take without
// modifying the SMT tree. Read-only classification.
func ClassifyEntry(p ClassifyParams) (*Classification, error) {
	h := &p.Entry.Header

	// No TargetRoot → commentary or new leaf.
	if h.TargetRoot == nil {
		if h.AuthorityPath == nil {
			return &Classification{
				Path:    PathResultCommentary,
				Reason:  "no Target_Root, no Authority_Path",
				Details: ClassificationDetails{IsCommentary: true},
			}, nil
		}
		return &Classification{
			Path:   PathResultNewLeaf,
			Reason: "Authority_Path set, no Target_Root → new leaf",
		}, nil
	}

	targetRoot := *h.TargetRoot

	// Locality check (Decision 47).
	if targetRoot.LogDID != p.LocalLogDID {
		return &Classification{
			Path:   PathResultPathD,
			Reason: "Target_Root references foreign log",
		}, nil
	}

	// Fetch target entry.
	targetMeta, err := p.Fetcher.Fetch(targetRoot)
	if err != nil || targetMeta == nil {
		return &Classification{
			Path:   PathResultPathD,
			Reason: "target entry not found or fetch error",
		}, nil
	}
	targetEntry, err := envelope.Deserialize(targetMeta.CanonicalBytes)
	if err != nil {
		return &Classification{
			Path:   PathResultPathD,
			Reason: "target entry deserialization failed",
		}, nil
	}

	// Leaf lookup.
	leafKey := smt.DeriveKey(targetRoot)
	leaf, err := p.LeafReader.Get(leafKey)
	if err != nil || leaf == nil {
		return &Classification{
			Path:   PathResultPathD,
			Reason: "target leaf not found in SMT",
		}, nil
	}

	// Evidence cap check.
	if len(h.EvidencePointers) > envelope.MaxEvidencePointers {
		if !isAuthoritySnapshot(h) {
			return &Classification{
				Path:   PathResultRejected,
				Reason: fmt.Sprintf("Evidence_Pointers %d exceeds cap %d (non-snapshot)", len(h.EvidencePointers), envelope.MaxEvidencePointers),
			}, fmt.Errorf("evidence cap exceeded")
		}
	}

	// No AuthorityPath → Path D.
	if h.AuthorityPath == nil {
		return &Classification{
			Path:   PathResultPathD,
			Reason: "Target_Root set but no Authority_Path",
		}, nil
	}

	details := ClassificationDetails{
		TargetLeafKey: &leafKey,
	}

	switch *h.AuthorityPath {
	case envelope.AuthoritySameSigner:
		return classifyPathA(h, targetEntry, &details)
	case envelope.AuthorityDelegation:
		return classifyPathB(h, targetEntry, p.Fetcher, p.LeafReader, p.LocalLogDID, &details)
	case envelope.AuthorityScopeAuthority:
		return classifyPathC(h, targetRoot, leaf, p.Fetcher, p.LeafReader, p.SchemaResolver, p.LocalLogDID, &details)
	default:
		return &Classification{
			Path:   PathResultPathD,
			Reason: fmt.Sprintf("unknown Authority_Path %d", *h.AuthorityPath),
		}, nil
	}
}

// ─────────────────────────────────────────────────────────────────────
// Path A (same signer)
// ─────────────────────────────────────────────────────────────────────

func classifyPathA(h *envelope.ControlHeader, target *envelope.Entry, d *ClassificationDetails) (*Classification, error) {
	if h.SignerDID != target.Header.SignerDID {
		return &Classification{
			Path:    PathResultPathD,
			Reason:  fmt.Sprintf("signer %s != target signer %s", h.SignerDID, target.Header.SignerDID),
			Details: *d,
		}, nil
	}
	return &Classification{
		Path:    PathResultPathA,
		Reason:  "same signer match",
		Details: *d,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// Path B (delegation)
// ─────────────────────────────────────────────────────────────────────

func classifyPathB(
	h *envelope.ControlHeader,
	target *envelope.Entry,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
	localLogDID string,
	d *ClassificationDetails,
) (*Classification, error) {
	if len(h.DelegationPointers) == 0 {
		return &Classification{
			Path:    PathResultPathD,
			Reason:  "Delegation_Pointers empty",
			Details: *d,
		}, nil
	}

	targetSignerDID := target.Header.SignerDID

	type delegInfo struct {
		signerDID   string
		delegateDID string
		used        bool
	}
	delegations := make([]delegInfo, 0, len(h.DelegationPointers))

	for i, ptr := range h.DelegationPointers {
		if ptr.LogDID != localLogDID {
			return &Classification{
				Path:   PathResultPathD,
				Reason: fmt.Sprintf("Delegation_Pointer[%d] references foreign log", i),
			}, nil
		}
		meta, err := fetcher.Fetch(ptr)
		if err != nil || meta == nil {
			return &Classification{
				Path:   PathResultPathD,
				Reason: fmt.Sprintf("Delegation_Pointer[%d] entry not found", i),
			}, nil
		}
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil || entry.Header.DelegateDID == nil {
			return &Classification{
				Path:   PathResultPathD,
				Reason: fmt.Sprintf("Delegation_Pointer[%d] invalid or missing Delegate_DID", i),
			}, nil
		}

		dLeafKey := smt.DeriveKey(ptr)
		dLeaf, lErr := leafReader.Get(dLeafKey)
		if lErr != nil || dLeaf == nil {
			return &Classification{
				Path:   PathResultPathD,
				Reason: fmt.Sprintf("Delegation_Pointer[%d] leaf not found", i),
			}, nil
		}
		if !dLeaf.OriginTip.Equal(ptr) {
			return &Classification{
				Path:   PathResultPathD,
				Reason: fmt.Sprintf("Delegation_Pointer[%d] not live (revoked)", i),
			}, nil
		}

		delegations = append(delegations, delegInfo{
			signerDID:   entry.Header.SignerDID,
			delegateDID: *entry.Header.DelegateDID,
		})
	}

	expectedDelegate := h.SignerDID
	visited := make(map[string]bool)
	depth := 0
	for depth < envelope.MaxDelegationPointers {
		found := false
		for i := range delegations {
			if delegations[i].used || delegations[i].delegateDID != expectedDelegate {
				continue
			}
			delegations[i].used = true
			found = true
			depth++
			if delegations[i].signerDID == targetSignerDID {
				d.DelegationDepth = depth
				return &Classification{
					Path:    PathResultPathB,
					Reason:  fmt.Sprintf("delegation chain connects at depth %d", depth),
					Details: *d,
				}, nil
			}
			if visited[delegations[i].signerDID] {
				return &Classification{
					Path:   PathResultRejected,
					Reason: "cycle in delegation chain",
				}, nil
			}
			visited[delegations[i].signerDID] = true
			expectedDelegate = delegations[i].signerDID
			break
		}
		if !found {
			break
		}
	}

	return &Classification{
		Path:   PathResultPathD,
		Reason: "delegation chain does not connect to target signer",
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// Path C (scope authority)
// ─────────────────────────────────────────────────────────────────────

func classifyPathC(
	h *envelope.ControlHeader,
	targetRoot types.LogPosition,
	leaf *types.SMTLeaf,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
	schemaResolver SchemaResolver,
	localLogDID string,
	d *ClassificationDetails,
) (*Classification, error) {
	if h.ScopePointer == nil || h.ScopePointer.LogDID != localLogDID {
		return &Classification{
			Path:   PathResultPathD,
			Reason: "Scope_Pointer nil or foreign",
		}, nil
	}

	// Fetch current scope state.
	scopeLeafKey := smt.DeriveKey(*h.ScopePointer)
	scopeLeaf, err := leafReader.Get(scopeLeafKey)
	if err != nil || scopeLeaf == nil {
		return &Classification{
			Path:   PathResultPathD,
			Reason: "scope leaf not found",
		}, nil
	}
	currentScopeMeta, err := fetcher.Fetch(scopeLeaf.OriginTip)
	if err != nil || currentScopeMeta == nil {
		return &Classification{
			Path:   PathResultPathD,
			Reason: "current scope entry not found",
		}, nil
	}
	currentScope, err := envelope.Deserialize(currentScopeMeta.CanonicalBytes)
	if err != nil {
		return &Classification{
			Path:   PathResultPathD,
			Reason: "scope entry deserialization failed",
		}, nil
	}

	// Authority set membership check.
	if _, ok := currentScope.Header.AuthoritySet[h.SignerDID]; !ok {
		return &Classification{
			Path:   PathResultPathD,
			Reason: fmt.Sprintf("signer %s not in scope authority set", h.SignerDID),
		}, nil
	}
	d.AuthoritySetSize = len(currentScope.Header.AuthoritySet)

	// OCC (Prior_Authority) — mirrors verifyPriorAuthority (concurrency.go) so
	// the classifier and live builder agree on acceptance (ORTHO-BUG-004).
	// Commutativity is decided via the shared resolveCommutativity helper.
	currentTip := leaf.AuthorityTip
	if currentTip.Equal(targetRoot) {
		if h.PriorAuthority != nil {
			return &Classification{
				Path:   PathResultRejected,
				Reason: "Prior_Authority must be nil when Authority_Tip == self",
			}, nil
		}
	} else {
		if h.PriorAuthority == nil {
			return &Classification{
				Path:   PathResultRejected,
				Reason: "Prior_Authority required when Authority_Tip != self",
			}, nil
		}
		if !h.PriorAuthority.Equal(currentTip) {
			if !resolveCommutativity(h, schemaResolver, fetcher) {
				return &Classification{
					Path:    PathResultRejected,
					Reason:  "strict OCC: Prior_Authority != Authority_Tip and schema is not commutative",
					Details: *d,
				}, nil
			}
			// Commutative schema: the Δ-window buffer is runtime-only state
			// not available to the read-only classifier. Admit provisionally
			// and flag so bridges know a runtime Δ-window check still gates
			// final acceptance.
			d.OCCNoteReadOnly = true
			return &Classification{
				Path:    PathResultPathC,
				Reason:  "commutative schema — runtime Δ-window check required",
				Details: *d,
			}, nil
		}
	}

	isScopeAmendment := h.ScopePointer.Equal(targetRoot) && len(h.AuthoritySet) > 0
	if isScopeAmendment {
		return &Classification{
			Path:    PathResultPathC,
			Reason:  "scope amendment execution (updates OriginTip)",
			Details: *d,
		}, nil
	}
	return &Classification{
		Path:    PathResultPathC,
		Reason:  "scope authority enforcement (updates AuthorityTip)",
		Details: *d,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// ClassifyBatch
// ─────────────────────────────────────────────────────────────────────

// ClassifyBatch classifies multiple entries. Read-only, no SMT modification.
// A nil schemaResolver keeps the batch under strict OCC (Decision 37).
func ClassifyBatch(
	entries []*envelope.Entry,
	positions []types.LogPosition,
	leafReader smt.LeafReader,
	fetcher types.EntryFetcher,
	schemaResolver SchemaResolver,
	logDID string,
) ([]Classification, error) {
	if len(entries) != len(positions) {
		return nil, fmt.Errorf("builder/classify: entries length %d != positions length %d", len(entries), len(positions))
	}
	results := make([]Classification, len(entries))
	for i, entry := range entries {
		c, _ := ClassifyEntry(ClassifyParams{
			Entry:          entry,
			Position:       positions[i],
			LeafReader:     leafReader,
			Fetcher:        fetcher,
			LocalLogDID:    logDID,
			SchemaResolver: schemaResolver,
		})
		if c != nil {
			results[i] = *c
		}
	}
	return results, nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func pathName(p PathResult) string {
	switch p {
	case PathResultCommentary:
		return "Commentary"
	case PathResultNewLeaf:
		return "NewLeaf"
	case PathResultPathA:
		return "PathA"
	case PathResultPathB:
		return "PathB"
	case PathResultPathC:
		return "PathC"
	case PathResultPathD:
		return "PathD"
	case PathResultRejected:
		return "Rejected"
	default:
		return fmt.Sprintf("Unknown(%d)", p)
	}
}
