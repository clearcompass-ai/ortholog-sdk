/*
Package builder — entry_classification.go provides read-only entry
classification without executing state changes.

ClassifyEntry mirrors the logic of processEntry (algorithm.go) but
never modifies the SMT tree. It answers "what path would this entry
take?" without side effects.

Use cases:
  - Pre-submission validation: "will this entry succeed?"
  - Monitoring dashboards: classify entries without replay.
  - Domain application UIs: show expected path before signing.
  - Debugging: understand why an entry was classified as Path D.

The classification result includes the path and a human-readable
reason explaining why that path was selected. When classification
fails (Path D), the reason identifies the specific check that failed.

Thread safety: ClassifyEntry takes a LeafReader (read-only SMT
access) instead of *smt.Tree. Multiple goroutines can classify
concurrently without contention.
*/
package builder

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Classification Result
// ─────────────────────────────────────────────────────────────────────

// ClassificationResult describes the expected path for an entry.
type ClassificationResult struct {
	// Path is the classified path result.
	Path PathResult

	// Reason is a human-readable explanation of why this path was selected.
	// For Path D and Rejected, explains the specific check that failed.
	Reason string
}

// String returns a compact representation: "PathA: same signer match".
func (r ClassificationResult) String() string {
	return fmt.Sprintf("%s: %s", pathName(r.Path), r.Reason)
}

// ─────────────────────────────────────────────────────────────────────
// ClassifyEntry — read-only path classification
// ─────────────────────────────────────────────────────────────────────

// ClassifyEntry determines what path an entry would take without
// modifying the SMT tree. This is a read-only operation.
//
// Parameters:
//   entry:       the entry to classify (deserialized).
//   leafReader:  read-only access to SMT leaves (LeafReader, not LeafStore).
//   fetcher:     retrieves entries by position (for delegation/scope checks).
//   schemaRes:   resolves schemas for OCC mode (optional, nil → strict OCC).
//   localLogDID: the local log's DID (for locality checks).
//
// Returns the classified path and a reason string.
func ClassifyEntry(
	entry *envelope.Entry,
	leafReader smt.LeafReader,
	fetcher EntryFetcher,
	schemaRes SchemaResolver,
	localLogDID string,
) ClassificationResult {
	h := &entry.Header

	// ── No TargetRoot ────────────────────────────────────────────────
	if h.TargetRoot == nil {
		if h.AuthorityPath == nil {
			return ClassificationResult{Path: PathResultCommentary, Reason: "no Target_Root, no Authority_Path"}
		}
		// Has AuthorityPath but no TargetRoot → new leaf.
		return ClassificationResult{Path: PathResultNewLeaf, Reason: "Authority_Path set, no Target_Root → new leaf"}
	}

	targetRoot := *h.TargetRoot

	// ── Locality check (Decision 47) ─────────────────────────────────
	if targetRoot.LogDID != localLogDID {
		return ClassificationResult{Path: PathResultPathD, Reason: "Target_Root references foreign log"}
	}

	// ── Fetch target entry ───────────────────────────────────────────
	targetMeta, err := fetcher.Fetch(targetRoot)
	if err != nil || targetMeta == nil {
		return ClassificationResult{Path: PathResultPathD, Reason: "target entry not found or fetch error"}
	}
	targetEntry, err := envelope.Deserialize(targetMeta.CanonicalBytes)
	if err != nil {
		return ClassificationResult{Path: PathResultPathD, Reason: "target entry deserialization failed"}
	}

	// ── Leaf lookup ──────────────────────────────────────────────────
	leafKey := smt.DeriveKey(targetRoot)
	leaf, err := leafReader.Get(leafKey)
	if err != nil || leaf == nil {
		return ClassificationResult{Path: PathResultPathD, Reason: "target leaf not found in SMT"}
	}

	// ── Evidence cap check ───────────────────────────────────────────
	if len(h.EvidencePointers) > envelope.MaxEvidencePointers {
		if !isAuthoritySnapshot(h) {
			return ClassificationResult{Path: PathResultRejected, Reason: fmt.Sprintf("Evidence_Pointers %d exceeds cap %d (non-snapshot)", len(h.EvidencePointers), envelope.MaxEvidencePointers)}
		}
	}

	// ── No AuthorityPath → Path D ────────────────────────────────────
	if h.AuthorityPath == nil {
		return ClassificationResult{Path: PathResultPathD, Reason: "Target_Root set but no Authority_Path"}
	}

	// ── Dispatch by AuthorityPath ────────────────────────────────────
	switch *h.AuthorityPath {
	case envelope.AuthoritySameSigner:
		return classifyPathA(h, targetEntry, leaf, leafKey)
	case envelope.AuthorityDelegation:
		return classifyPathB(h, targetEntry, leaf, leafKey, fetcher, leafReader, localLogDID)
	case envelope.AuthorityScopeAuthority:
		return classifyPathC(h, targetRoot, leaf, leafKey, fetcher, leafReader, schemaRes, localLogDID)
	default:
		return ClassificationResult{Path: PathResultPathD, Reason: fmt.Sprintf("unknown Authority_Path %d", *h.AuthorityPath)}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Path A classification (same signer)
// ─────────────────────────────────────────────────────────────────────

func classifyPathA(h *envelope.ControlHeader, target *envelope.Entry, leaf *types.SMTLeaf, leafKey [32]byte) ClassificationResult {
	if h.SignerDID != target.Header.SignerDID {
		return ClassificationResult{
			Path:   PathResultPathD,
			Reason: fmt.Sprintf("signer %s != target signer %s", h.SignerDID, target.Header.SignerDID),
		}
	}
	return ClassificationResult{Path: PathResultPathA, Reason: "same signer match"}
}

// ─────────────────────────────────────────────────────────────────────
// Path B classification (delegation)
// ─────────────────────────────────────────────────────────────────────

func classifyPathB(
	h *envelope.ControlHeader,
	target *envelope.Entry,
	leaf *types.SMTLeaf,
	leafKey [32]byte,
	fetcher EntryFetcher,
	leafReader smt.LeafReader,
	localLogDID string,
) ClassificationResult {
	if len(h.DelegationPointers) == 0 {
		return ClassificationResult{Path: PathResultPathD, Reason: "Delegation_Pointers empty"}
	}

	targetSignerDID := target.Header.SignerDID

	// Load and validate all delegation entries.
	type delegInfo struct {
		signerDID   string
		delegateDID string
		used        bool
	}
	delegations := make([]delegInfo, 0, len(h.DelegationPointers))

	for i, ptr := range h.DelegationPointers {
		if ptr.LogDID != localLogDID {
			return ClassificationResult{
				Path:   PathResultPathD,
				Reason: fmt.Sprintf("Delegation_Pointer[%d] references foreign log", i),
			}
		}
		meta, err := fetcher.Fetch(ptr)
		if err != nil || meta == nil {
			return ClassificationResult{
				Path:   PathResultPathD,
				Reason: fmt.Sprintf("Delegation_Pointer[%d] entry not found", i),
			}
		}
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil || entry.Header.DelegateDID == nil {
			return ClassificationResult{
				Path:   PathResultPathD,
				Reason: fmt.Sprintf("Delegation_Pointer[%d] invalid or missing Delegate_DID", i),
			}
		}

		// Check liveness.
		dLeafKey := smt.DeriveKey(ptr)
		dLeaf, lErr := leafReader.Get(dLeafKey)
		if lErr != nil || dLeaf == nil {
			return ClassificationResult{
				Path:   PathResultPathD,
				Reason: fmt.Sprintf("Delegation_Pointer[%d] leaf not found", i),
			}
		}
		if !dLeaf.OriginTip.Equal(ptr) {
			return ClassificationResult{
				Path:   PathResultPathD,
				Reason: fmt.Sprintf("Delegation_Pointer[%d] not live (OriginTip advanced)", i),
			}
		}

		delegations = append(delegations, delegInfo{
			signerDID:   entry.Header.SignerDID,
			delegateDID: *entry.Header.DelegateDID,
		})
	}

	// Walk the chain: start from action signer, try to reach target signer.
	expectedDelegate := h.SignerDID
	visited := make(map[string]bool)
	for depth := 0; depth < 3; depth++ {
		found := false
		for i := range delegations {
			if delegations[i].used {
				continue
			}
			if delegations[i].delegateDID != expectedDelegate {
				continue
			}
			delegations[i].used = true
			found = true
			if delegations[i].signerDID == targetSignerDID {
				return ClassificationResult{Path: PathResultPathB, Reason: fmt.Sprintf("delegation chain connects at depth %d", depth+1)}
			}
			if visited[delegations[i].signerDID] {
				return ClassificationResult{Path: PathResultRejected, Reason: "cycle in delegation chain"}
			}
			visited[delegations[i].signerDID] = true
			expectedDelegate = delegations[i].signerDID
			break
		}
		if !found {
			break
		}
	}

	usedCount := 0
	for _, d := range delegations {
		if d.used {
			usedCount++
		}
	}
	if usedCount >= 3 {
		return ClassificationResult{Path: PathResultRejected, Reason: "delegation chain exceeded max depth"}
	}
	return ClassificationResult{Path: PathResultPathD, Reason: "delegation chain does not connect to target signer"}
}

// ─────────────────────────────────────────────────────────────────────
// Path C classification (scope authority)
// ─────────────────────────────────────────────────────────────────────

func classifyPathC(
	h *envelope.ControlHeader,
	targetRoot types.LogPosition,
	leaf *types.SMTLeaf,
	leafKey [32]byte,
	fetcher EntryFetcher,
	leafReader smt.LeafReader,
	schemaRes SchemaResolver,
	localLogDID string,
) ClassificationResult {
	// Scope pointer validation.
	if h.ScopePointer == nil || h.ScopePointer.LogDID != localLogDID {
		return ClassificationResult{Path: PathResultPathD, Reason: "Scope_Pointer nil or foreign"}
	}

	// Fetch current scope state.
	scopeLeafKey := smt.DeriveKey(*h.ScopePointer)
	scopeLeaf, err := leafReader.Get(scopeLeafKey)
	if err != nil || scopeLeaf == nil {
		return ClassificationResult{Path: PathResultPathD, Reason: "scope leaf not found"}
	}
	currentScopeMeta, err := fetcher.Fetch(scopeLeaf.OriginTip)
	if err != nil || currentScopeMeta == nil {
		return ClassificationResult{Path: PathResultPathD, Reason: "current scope entry not found"}
	}
	currentScope, err := envelope.Deserialize(currentScopeMeta.CanonicalBytes)
	if err != nil {
		return ClassificationResult{Path: PathResultPathD, Reason: "scope entry deserialization failed"}
	}

	// Authority set membership check.
	if !currentScope.Header.AuthoritySetContains(h.SignerDID) {
		return ClassificationResult{
			Path:   PathResultPathD,
			Reason: fmt.Sprintf("signer %s not in scope authority set", h.SignerDID),
		}
	}

	// Approval pointers validation.
	if len(h.ApprovalPointers) > 0 {
		for i, ptr := range h.ApprovalPointers {
			if ptr.LogDID != localLogDID {
				return ClassificationResult{Path: PathResultRejected, Reason: fmt.Sprintf("Approval_Pointer[%d] references foreign log", i)}
			}
			meta, fetchErr := fetcher.Fetch(ptr)
			if fetchErr != nil || meta == nil {
				return ClassificationResult{Path: PathResultRejected, Reason: fmt.Sprintf("Approval_Pointer[%d] not found", i)}
			}
			approval, desErr := envelope.Deserialize(meta.CanonicalBytes)
			if desErr != nil {
				return ClassificationResult{Path: PathResultRejected, Reason: fmt.Sprintf("Approval_Pointer[%d] deserialization failed", i)}
			}
			if !currentScope.Header.AuthoritySetContains(approval.Header.SignerDID) {
				return ClassificationResult{Path: PathResultRejected, Reason: fmt.Sprintf("Approval_Pointer[%d] signer not in authority set", i)}
			}
		}
	}

	// OCC verification (Prior_Authority).
	currentTip := leaf.AuthorityTip
	if currentTip.Equal(targetRoot) {
		// Base case: no prior enforcement. Prior_Authority must be nil.
		if h.PriorAuthority != nil {
			return ClassificationResult{Path: PathResultRejected, Reason: "Prior_Authority must be nil when Authority_Tip == self"}
		}
	} else {
		// Enforcement history exists. Prior_Authority required.
		if h.PriorAuthority == nil {
			return ClassificationResult{Path: PathResultRejected, Reason: "Prior_Authority required when Authority_Tip != self"}
		}
		// Check OCC match (strict or commutative).
		if !h.PriorAuthority.Equal(currentTip) {
			// Check commutative OCC if schema declares it.
			// Without a DeltaWindowBuffer in read-only mode, we can only
			// check the current tip. Report as potential mismatch.
			isCommutative := false
			if h.SchemaRef != nil && schemaRes != nil {
				resolution, resErr := schemaRes.Resolve(*h.SchemaRef, fetcher)
				if resErr == nil && resolution != nil {
					isCommutative = resolution.IsCommutative
				}
			}
			if isCommutative {
				return ClassificationResult{
					Path:   PathResultPathC,
					Reason: "commutative schema — Prior_Authority may be within delta window (cannot verify without buffer)",
				}
			}
			return ClassificationResult{
				Path:   PathResultRejected,
				Reason: fmt.Sprintf("strict OCC: Prior_Authority %s != current Authority_Tip %s", h.PriorAuthority, currentTip),
			}
		}
	}

	// Classify sub-type: amendment vs enforcement.
	isScopeAmendment := h.ScopePointer.Equal(targetRoot) && len(h.AuthoritySet) > 0
	if isScopeAmendment {
		return ClassificationResult{Path: PathResultPathC, Reason: "scope amendment execution (updates OriginTip)"}
	}
	return ClassificationResult{Path: PathResultPathC, Reason: "scope authority enforcement (updates AuthorityTip)"}
}

// ─────────────────────────────────────────────────────────────────────
// ClassifyBatch — classify multiple entries
// ─────────────────────────────────────────────────────────────────────

// ClassifyBatch classifies multiple entries and returns per-entry results.
// Read-only: no SMT state is modified. Each entry is classified
// independently against the current tree state.
func ClassifyBatch(
	entries []*envelope.Entry,
	leafReader smt.LeafReader,
	fetcher EntryFetcher,
	schemaRes SchemaResolver,
	localLogDID string,
) []ClassificationResult {
	results := make([]ClassificationResult, len(entries))
	for i, entry := range entries {
		results[i] = ClassifyEntry(entry, leafReader, fetcher, schemaRes, localLogDID)
	}
	return results
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// pathName returns a human-readable name for a PathResult.
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
