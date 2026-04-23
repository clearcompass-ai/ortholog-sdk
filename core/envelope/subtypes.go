/*
Package envelope — subtypes.go exposes predicates that identify the
named entry subtypes the protocol specification calls out: cosignature
commentary, credential entries, scope creation, scope amendment, scope
enforcement, delegation entries, and authority snapshots.

The predicates are pure functions over ControlHeader. They are shape-only:
they report whether a header has the structural markers of a subtype, not
whether the entry is cryptographically admissible on that path (the
builder/verifier still enforce signature, locality, OCC, and authority-set
membership).

Why predicates rather than a discriminant enum field: the protocol wire
format is intentionally path-structural. A single entry may simultaneously
be a "credential" (carries SubjectIdentifier) and a "new leaf" (no
TargetRoot) and a "same-signer root entity" (AuthorityPath = SameSigner).
The subtypes named in the spec are orthogonal views over the same header,
not mutually exclusive tags. These predicates let external callers query
any one view without committing to a single taxonomy.

Spec alignment: the five-way classification in the transparency spec
(Commentary / New Leaf / Direct Amendment / Delegation Chain / Scope
Authority) is provided by PathResult in builder/api.go. The spec's
named subtypes within those classes (Cosignature Commentary,
Credential Entries, Scope Creation Entries, Delegation Entry,
Scope Enforcement, Scope Amendment, Authority Snapshots) are the
predicates declared here.
*/
package envelope

import "github.com/clearcompass-ai/ortholog-sdk/types"

// MaxDelegationDepth is the protocol's hop cap for Path B delegation
// chains. Mechanically equal to MaxDelegationPointers — the array size
// cap and the chain walk depth cap are pinned to the same value so the
// chain cannot legally exceed the array's capacity. Exported so
// transparency-protocol documentation and bridges can cite a stable
// constant name rather than a hard-coded literal.
const MaxDelegationDepth = MaxDelegationPointers

// IsCommentary reports whether the header has no SMT impact: no TargetRoot
// and no AuthorityPath. Pure commentary, cosignatures, anchors, and
// recovery requests all satisfy this.
func IsCommentary(h *ControlHeader) bool {
	if h == nil {
		return false
	}
	return h.TargetRoot == nil && h.AuthorityPath == nil
}

// IsCosignatureCommentary reports whether the header is a cosignature
// commentary entry — a commentary entry that binds itself to another
// entry's log position via CosignatureOf. Spec subtype of class 1.
func IsCosignatureCommentary(h *ControlHeader) bool {
	if h == nil {
		return false
	}
	return IsCommentary(h) && h.CosignatureOf != nil
}

// IsNewLeaf reports whether the header provisions a new SMT leaf:
// AuthorityPath is set and TargetRoot is nil. Root entities, scope
// creations, schema entries, and delegation entries all satisfy this.
func IsNewLeaf(h *ControlHeader) bool {
	if h == nil {
		return false
	}
	return h.TargetRoot == nil && h.AuthorityPath != nil
}

// IsCredentialEntry reports whether the header carries a credential
// subject identifier on a new-leaf entry. Spec subtype of class 2.
// The SubjectIdentifier is opaque to the builder; domains interpret it.
func IsCredentialEntry(h *ControlHeader) bool {
	if h == nil {
		return false
	}
	return IsNewLeaf(h) && len(h.SubjectIdentifier) > 0
}

// IsScopeCreation reports whether the header provisions a new scope
// entity — a new leaf whose AuthoritySet declares the initial governing
// membership. Spec subtype of class 2.
func IsScopeCreation(h *ControlHeader) bool {
	if h == nil {
		return false
	}
	return IsNewLeaf(h) && len(h.AuthoritySet) > 0
}

// IsDirectAmendment reports whether the header is a same-signer
// amendment: TargetRoot set, AuthorityPath = SameSigner. Spec class 3.
func IsDirectAmendment(h *ControlHeader) bool {
	if h == nil || h.AuthorityPath == nil || h.TargetRoot == nil {
		return false
	}
	return *h.AuthorityPath == AuthoritySameSigner
}

// IsDelegationEntry reports whether the header establishes a delegation
// by populating DelegateDID. Delegation entries are Path A + new-leaf
// in shape (same-signer institution authorizing a role-specific key).
// Spec subtype of class 3 (Direct Amendment lane).
func IsDelegationEntry(h *ControlHeader) bool {
	if h == nil {
		return false
	}
	return h.DelegateDID != nil && *h.DelegateDID != ""
}

// IsDelegationChain reports whether the header is a Path B delegation
// chain entry: TargetRoot set, AuthorityPath = Delegation, with at
// least one DelegationPointer. Spec class 4.
func IsDelegationChain(h *ControlHeader) bool {
	if h == nil || h.AuthorityPath == nil || h.TargetRoot == nil {
		return false
	}
	return *h.AuthorityPath == AuthorityDelegation && len(h.DelegationPointers) > 0
}

// IsScopeAuthority reports whether the header is a Path C scope-authority
// entry: TargetRoot set, AuthorityPath = ScopeAuthority, with a
// ScopePointer. Spec class 5.
func IsScopeAuthority(h *ControlHeader) bool {
	if h == nil || h.AuthorityPath == nil || h.TargetRoot == nil {
		return false
	}
	return *h.AuthorityPath == AuthorityScopeAuthority && h.ScopePointer != nil
}

// IsScopeAmendment reports whether the header mutates the scope's own
// structure — a Path C entry whose ScopePointer equals the TargetRoot
// and which carries a new AuthoritySet. Advances the scope's OriginTip.
// Spec subtype of class 5.
func IsScopeAmendment(h *ControlHeader) bool {
	if !IsScopeAuthority(h) {
		return false
	}
	return h.ScopePointer.Equal(*h.TargetRoot) && len(h.AuthoritySet) > 0
}

// IsScopeEnforcement reports whether the header is a Path C enforcement
// action — a scope-authority entry that targets some other entity rather
// than the scope itself, or targets the scope without an AuthoritySet
// (e.g., a scope removal). Advances the target's AuthorityTip. Spec
// subtype of class 5.
func IsScopeEnforcement(h *ControlHeader) bool {
	if !IsScopeAuthority(h) {
		return false
	}
	return !IsScopeAmendment(h)
}

// NewAuthoritySnapshotRefFromHeader extracts a snapshot descriptor from
// a ControlHeader. Returns nil, false when the header does not satisfy
// IsAuthoritySnapshotShape. Callers holding only a *Entry can pass
// &entry.Header.
//
// The constructor lives here (envelope → types direction) because
// types already cannot import envelope without creating a cycle; the
// AuthoritySnapshotRef descriptor is declared in package types so
// read-side consumers don't have to import envelope just to hold a
// snapshot reference.
func NewAuthoritySnapshotRefFromHeader(h *ControlHeader) (*types.AuthoritySnapshotRef, bool) {
	if !IsAuthoritySnapshotShape(h) {
		return nil, false
	}
	ptrs := make([]types.LogPosition, len(h.EvidencePointers))
	copy(ptrs, h.EvidencePointers)
	return &types.AuthoritySnapshotRef{
		TargetRoot:       *h.TargetRoot,
		PriorAuthority:   *h.PriorAuthority,
		EvidencePointers: ptrs,
	}, true
}
