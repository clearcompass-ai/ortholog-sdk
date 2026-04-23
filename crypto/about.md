# Log Entry Classification Specification

This document is the authoritative mapping between the Ortholog SDK
implementation and the formal transparency-protocol model (RFC-6962 /
Trillian style). It reconciles the five path-classification classes,
their named subtypes, and their structural identifiers against the
actual code under `core/envelope/`, `builder/`, `verifier/`, and
`types/`.

Each class below lists:

* **Structural identifiers** — the ControlHeader fields that a parser
  reads to route the entry. Field names match
  `core/envelope/control_header.go`.
* **SMT mutation** — the leaf-state transition computed by
  `builder/algorithm.go`.
* **Authorization requirement** — the validation the builder enforces
  before accepting the entry.
* **Subtypes** — the named variants within the class, each with the
  predicate in `core/envelope/subtypes.go` that identifies it.

## Quick Reference Matrix

| Class | `TargetRoot` | `AuthorityPath` | SMT Impact | Authorization | `PathResult` |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1. Commentary | `nil` | `nil` | zero | signature only | `PathResultCommentary` |
| 2. New Leaf | `nil` | defined | provision leaf | signature + path validity | `PathResultNewLeaf` |
| 3. Direct Amendment | set | `AuthoritySameSigner` | advances `OriginTip` | `SignerDID` strict match | `PathResultPathA` |
| 4. Delegation Chain | set | `AuthorityDelegation` | advances `OriginTip` | hop-by-hop provenance + liveness | `PathResultPathB` |
| 5. Scope Authority | set | `AuthorityScopeAuthority` | advances `AuthorityTip` or `OriginTip` | historical authority-set membership | `PathResultPathC` |

Residual buckets, distinct from the five classes:

| Bucket | Meaning |
| :--- | :--- |
| `PathResultPathD` | entry structurally valid but did not qualify for any authority path (foreign log, missing target, authority mismatch, stale OCC). SMT untouched. |
| `PathResultRejected` | entry violates a structural invariant (evidence-pointer cap, delegation cycle, approval signer not in authority set). Should not have been admitted. |

---

## Class 1 — Commentary Entries

**Description.** Verifiable, immutable statements attached to the log
without altering the state of any entity.

**Structural identifiers.**

* `TargetRoot` = `nil`
* `AuthorityPath` = `nil`

**SMT mutation.** None. `processEntry` in `builder/algorithm.go:48-51`
returns `PathResultCommentary` immediately.

**Authorization requirement.** Valid signature over the canonical bytes.
No SMT state is read. Destination binding
(`ControlHeader.Destination`) still applies: an entry signed for
exchange A cannot be verified against exchange B.

**Predicate.** `envelope.IsCommentary(h)`.

### Subtype 1a — Cosignature Commentary

A commentary entry that cryptographically references another entry by
its exact log position via `ControlHeader.CosignatureOf`. Used by
decentralized parties to attach approval to an action without
mutating the referenced entity.

* Additional identifier: `CosignatureOf` = `<LogPosition>` (non-nil).
* Predicate: `envelope.IsCosignatureCommentary(h)`.
* Builder: `builder.BuildCosignature`.
* Position-binding check: `verifier.IsCosignatureOf` enforces that
  both the pointer and the underlying position match
  (`verifier/cosignature.go:94`). This closes ORTHO-BUG-009/015/016:
  an attacker cannot replay a cosignature against a different entry
  by manipulating only the LogPosition value.

---

## Class 2 — New Leaf Entries

**Description.** Genesis events that establish a root entity and bind
it to its initial tips.

**Structural identifiers.**

* `TargetRoot` = `nil`
* `AuthorityPath` = `AuthoritySameSigner` | `AuthorityDelegation` | `AuthorityScopeAuthority`

**SMT mutation.** Provisions a new leaf at `smt.DeriveKey(pos)` with
`OriginTip = pos` and `AuthorityTip = pos`
(`builder/algorithm.go:52-61`).

**Authorization requirement.** Signature verification plus validity of
the declared `AuthorityPath`. The self-binding means there is no
target to match against; the entry is its own anchor.

**Predicate.** `envelope.IsNewLeaf(h)`.

### Subtype 2a — Credential Entries

A new-leaf entry that binds the record to an opaque subject identifier
(e.g., a tamper-proof license). The builder treats the identifier as
opaque bytes; domains interpret its structure.

* Additional identifier: `SubjectIdentifier` non-empty.
* Predicate: `envelope.IsCredentialEntry(h)`.
* Validity-period check (when the entry's schema declares one):
  `verifier.evaluateCredentialValidity`
  (`verifier/condition_evaluator.go:369`).

### Subtype 2b — Scope Creation Entries

A new-leaf entry that provisions a decentralized governing body by
declaring its initial `AuthoritySet` membership.

* Additional identifier: `AuthoritySet` non-empty.
* Predicate: `envelope.IsScopeCreation(h)`.
* Builder: `builder.BuildScopeCreation`. Enforces that `SignerDID`
  is itself a member of the set.

---

## Class 3 — Direct Amendment (Same Signer)

**Description.** Unilateral state transition where the original creator
of an entity updates, amends, or revokes its own record.

**Structural identifiers.**

* `TargetRoot` = `<LogPosition>`
* `AuthorityPath` = `AuthoritySameSigner`

**SMT mutation.** Advances the target leaf's `OriginTip` to the new
entry's position
(`builder/algorithm.go:112-146`, `computeOriginTipUpdate`). When
`TargetIntermediate` is set, that leaf's `OriginTip` is advanced in
the same compute-then-apply transaction.

**Authorization requirement.** The submitting `SignerDID` must exactly
match the target entity's original `SignerDID`
(`builder/algorithm.go:122-124`). No delegation, no scope.

**Predicate.** `envelope.IsDirectAmendment(h)`.

### Subtype 3a — Delegation Entry

A Path A entry (or more commonly a Path A new-leaf entry) that
populates `DelegateDID`, cryptographically binding a role-specific
key to the institution's root identity. Subsequent Path B entries
can chain through this delegation.

* Additional identifier: `DelegateDID` non-nil and non-empty.
* Predicate: `envelope.IsDelegationEntry(h)`.
* Builder: `builder.BuildDelegation`.
* Liveness: a delegation is "live" when its leaf's
  `OriginTip` still equals the delegation position (not revoked,
  not amended). Path B enforces this at every hop — see Class 4.

---

## Class 4 — Delegation Chain

**Description.** Hierarchical authorization: designated intermediate
officials take action on behalf of a root institution.

**Structural identifiers.**

* `TargetRoot` = `<LogPosition>`
* `AuthorityPath` = `AuthorityDelegation`
* `DelegationPointers` non-empty, each a `LogPosition`.

**SMT mutation.** Advances the target's `OriginTip`. `TargetIntermediate`
is honored the same way as in Path A.

**Authorization requirement.** `builder/algorithm.go:152-260` performs a
rigorous hop-by-hop provenance check.

* **Constraint A — chain connectivity.** Each hop's `DelegateDID` must
  match the *previous* hop's `SignerDID`, starting from the submitting
  `SignerDID` and terminating when a hop's `SignerDID` equals the
  target's `SignerDID`. The submitting key must be transitively
  authorized by the target root.
* **Constraint B — maximum chain depth.** `envelope.MaxDelegationDepth`
  (= `envelope.MaxDelegationPointers` = 3). Wire-format admission rejects
  arrays longer than the cap; the runtime walk will not advance beyond
  the cap even if the array fits
  (`builder/algorithm.go:202-258`). Exceeding the cap by exhausting
  every slot produces `PathResultRejected`, not `PathResultPathD` —
  this is a structural invariant violation.
* **Constraint C — liveness at every hop.** For each pointer, the
  referenced delegation leaf's `OriginTip` must still equal the
  pointer itself (`builder/algorithm.go:193-195`). A revoked or
  superseded delegation breaks the chain.
* **Constraint D — no cycles.** A signer appearing twice in the walk
  produces `PathResultRejected` (`builder/algorithm.go:238-240`).
* **Constraint E — locality.** Every pointer must reference the local
  log (`builder/algorithm.go:177-179`). Cross-log delegation chains
  are rejected at admission per Decision 47; they are not a supported
  authorization primitive. Cross-log provenance is carried separately
  via mirror/anchor commentary entries.

**Predicate.** `envelope.IsDelegationChain(h)`.

---

## Class 5 — Scope Authority

**Description.** Decentralized, consortium-based governance. The most
rigorous authorization mechanism.

**Structural identifiers.**

* `TargetRoot` = `<LogPosition>`
* `AuthorityPath` = `AuthorityScopeAuthority`
* `ScopePointer` = `<LogPosition>` (references the governing scope)

**SMT mutation.** Branch-dependent:

* **Scope enforcement** → advances target's `AuthorityTip`
  (`builder/algorithm.go:358-371`, `computeAuthorityTipUpdate`).
* **Scope amendment** → advances the scope's own `OriginTip`
  (`builder/algorithm.go:345-357`, `computeOriginTipUpdate`).

**Authorization requirement.** `builder/algorithm.go:266-378` performs
a historical authority-set resolution:

1. **Query position.** The set is resolved at `PriorAuthority` (the
   observation the signer committed to at signing time), or at the
   scope's own position when `PriorAuthority` is nil (scope creation
   case). Decision 52.
2. **Set derivation.** `scope.AuthorizedSetAtPosition` walks scope
   history back through prior amendments. Structural violations
   (cycle, cross-log walk, empty set, malformed entry, walk-too-deep,
   pre-creation observation) surface as `PathResultRejected`
   (`builder/algorithm.go:314-321`).
3. **Membership.** The submitting `SignerDID` must be a member of the
   resolved set.
4. **Approval pointers.** When `ApprovalPointers` is non-empty, every
   approval's signer must also be in the resolved set
   (`builder/algorithm.go:330-334`).
5. **OCC (Prior_Authority).** `verifyPriorAuthority` enforces strict
   OCC by default; schemas that declare commutative ordering may admit
   provisionally subject to a runtime Δ-window check
   (`builder/concurrency.go`).

**Predicate.** `envelope.IsScopeAuthority(h)`.

### Subtype 5a — Scope Enforcement

Constraint, conditional lock, or revocation placed on a target entity
by the scope's governing board. Advances the target's `AuthorityTip`.
Evidence pointers are capped at `envelope.MaxEvidencePointers` (32).

* Predicate: `envelope.IsScopeEnforcement(h)`.
* Builders: `builder.BuildEnforcement`, `builder.BuildScopeRemoval`.

### Subtype 5b — Scope Amendment

The governing board mutates its own structure (e.g., adds or removes a
member). The `ScopePointer` equals the `TargetRoot` (self-referencing),
and `AuthoritySet` carries the new membership. Advances the scope's
`OriginTip`.

* Predicate: `envelope.IsScopeAmendment(h)`.
* Builder: `builder.BuildScopeAmendment`.

### Subtype 5c — Authority Snapshots

A specialized shortcut entry. A snapshot compresses a range of prior
enforcement actions into a single entry's `EvidencePointers` array, so
that authority-chain walkers can skip hop-by-hop reconstruction. Light
clients use snapshots to bound verification cost.

* **Shape.** Any Path C entry that carries both `TargetRoot` and
  `PriorAuthority`. Detected by `envelope.IsAuthoritySnapshotShape`.
  The SDK shape-detects snapshots rather than introducing a dedicated
  `AuthorityPath` constant — a snapshot is structurally an
  enforcement that happens to carry evidence.
* **Evidence cap exemption.** Snapshots are exempt from the
  `MaxEvidencePointers` (32) cap. The exemption is enforced in
  `core/envelope/serialize.go:286` and `builder/algorithm.go:86-90`.
* **Descriptor.** `types.AuthoritySnapshotRef` carries the
  read-side view; constructed from a header via
  `envelope.NewAuthoritySnapshotRefFromHeader`.
* **SMT effect.** Identical to scope enforcement — advances
  `AuthorityTip`. The evidence array is the entry's semantic payload,
  not an SMT mutation.
* **Verifier role.** `verifier/authority_evaluator.go` treats snapshot
  entries as authority-chain terminators: a walk that reaches a
  snapshot may consume its `EvidencePointers` in lieu of
  continuing back through prior amendments.

---

## Residual Paths

### PathResultPathD

An entry that was admitted to the log but did not qualify for any
authority path. The SMT is untouched. The entry is retained for audit
but has no state-advancing effect. Common causes:

* `TargetRoot` references a foreign log (Decision 47 locality).
* Target entry or leaf not found in the local state.
* `SignerDID` does not match the target signer (Path A), the
  delegation chain does not connect (Path B), or the signer is not in
  the scope's authority set (Path C).
* OCC mismatch on a non-commutative schema.

### PathResultRejected

An entry that violates a structural invariant and should never have
been admitted. Operators use this classification to flag anomalies
upstream. Common causes:

* `EvidencePointers` exceeds `MaxEvidencePointers` on a non-snapshot
  entry.
* `DelegationPointers` forms a cycle or exceeds `MaxDelegationDepth`.
* Scope history walk detects a cycle, cross-log link, empty set,
  malformed entry, or a pre-creation observation.
* An `ApprovalPointer` references an entry whose signer is not in the
  resolved scope authority set.
* `PriorAuthority` invariants violated (nil when required, non-nil
  when the tip equals self).

---

## Concepts in the SDK Beyond the Formal Spec

The canonical transparency model covers the five classes above. The
SDK also implements the following wire-level and concurrency concerns
that a formal protocol specification would need to codify.

* **Protocol versioning.** `ControlHeader.ProtocolVersion` is the
  first field of the canonical preamble. The SDK currently emits
  version 7; older versions are rejected at deserialize
  (`core/envelope/api.go`).
* **Destination binding.** `ControlHeader.Destination` is part of the
  canonical hash, so an entry signed for exchange A cannot be
  verified against exchange B. This is the protocol-level defense
  against cross-exchange replay
  (`core/envelope/control_header.go:74-87`).
* **Dual timestamps.** `ControlHeader.EventTime` is the
  domain-asserted timestamp; the operator-asserted `Log_Time` is
  supplied separately by the log admission layer.
* **Per-entry schema binding.** `ControlHeader.SchemaRef` pins the
  governing schema for the entry. Verifiers follow the reference to
  resolve activation delay, cosignature threshold, credential
  validity, and other schema-declared parameters (Decision 37).
* **Intermediate cascades.** `ControlHeader.TargetIntermediate`
  optionally references an intermediate entity whose `OriginTip`
  (Paths A and B) or `AuthorityTip` (Path C enforcement) is advanced
  in the same compute-then-apply transaction as the main target.
* **Δ-window commutative OCC.** `builder/concurrency.go` and
  `builder/api.go` implement a bounded-window relaxation of strict
  OCC for schemas that declare commutative authority ordering. The
  default window is 10 slots; schemas may declare their own.
* **Proof-of-work admission (Mode B).** `ControlHeader.AdmissionProof`
  carries a length-prefixed `AdmissionProofBody` with difficulty,
  epoch, optional submitter commit, nonce, and hash — isolating
  malformed proofs from adjacent-field bleed on parse (SDK-3).
* **Multi-signature envelopes.** `Entry.Signatures` is a slice;
  cosignatures can be embedded alongside the primary signature
  instead of emitted as separate commentary entries. The signature
  section is tacked on after the signing payload, so the circular
  hash dependency does not arise.
* **Evidence-pointer capacity.** Routine entries are capped at
  `envelope.MaxEvidencePointers` = 32. Snapshot entries are exempt
  (see Subtype 5c). The cap is enforced at serialize time and at the
  classifier; it is a structural invariant, not a schema parameter.

---

## File Map

| Concept | Authoritative file |
| :--- | :--- |
| Control Header fields | `core/envelope/control_header.go` |
| Protocol constants (versions, caps) | `core/envelope/api.go` |
| Subtype predicates | `core/envelope/subtypes.go` |
| Authority-snapshot shape predicate | `core/envelope/serialize.go` (`IsAuthoritySnapshotShape`) |
| Authority-snapshot descriptor | `types/snapshots.go` |
| Path classification (read-only) | `builder/entry_classification.go` |
| Path classification (apply) | `builder/algorithm.go` |
| Entry builders (18 named constructors) | `builder/entry_builders.go` |
| Scope history resolution | `core/scope/` |
| Cosignature position binding | `verifier/cosignature.go` |
| Delegation provenance (read-only) | `verifier/authority_evaluator.go` |
| Authority evaluator (incl. snapshot terminator) | `verifier/authority_evaluator.go` |
| Δ-window commutative OCC | `builder/concurrency.go` |

---

## Reconciliation Notes

The transparency-protocol model and the SDK historically diverged on
four points. Each is now addressed:

1. **Credential Entries** were previously not a named subtype.
   `envelope.IsCredentialEntry` now identifies them; `SubjectIdentifier`
   remains optional on new-leaf entries but is the canonical marker.
2. **Scope Enforcement vs. Scope Amendment** were previously
   shape-discriminated inside `classifyPathC` without external names.
   `envelope.IsScopeEnforcement` / `envelope.IsScopeAmendment` now
   expose the same discriminant.
3. **Authority Snapshots** were previously shape-detected but lacked a
   usable read-side descriptor — `AuthoritySnapshotRef` was a
   seven-line stub. It now carries documentation, a constructor
   (`envelope.NewAuthoritySnapshotRefFromHeader`), and an
   `IsActiveShortcut` helper.
4. **Max delegation depth** was previously a hard-coded private
   `maxDelegationDepth = 3` constant in `builder/algorithm.go`. The
   protocol cap is now exposed as `envelope.MaxDelegationDepth` (an
   alias of `MaxDelegationPointers`), so external code and
   documentation can cite a single stable name.

Cross-log delegation chains remain deliberately rejected at admission
(Decision 47). The spec's generality on hop-by-hop provenance is
intentionally narrowed in this SDK; cross-log provenance is carried
via mirror/anchor commentary (Class 1), not via Path B.
