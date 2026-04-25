// Package lifecycle — artifact_access_mutation_switches.go holds
// the ADR-005 §6 mutation-audit switches for the lifecycle-side
// artifact access surface (artifact_access.go and recovery.go).
// Declared in their own file so the audit-v775 runner's line-
// local rewrite can target exactly one declaration per constant.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING ANY muEnable* CONSTANT.   │
//	├─────────────────────────────────────────────────────────────┤
//	│  These constants gate the lifecycle-layer integrity checks  │
//	│  every artifact grant + reconstruction path depends on.     │
//	│  Setting any to false permanently is a security regression  │
//	│  that admits silent decryption without commitments,         │
//	│  silent grant authorization bypass, witness-cosignature     │
//	│  forgery, or wrong-size key material into the recovery     │
//	│  flow. The switches exist so the audit runner can flip      │
//	│  them and observe that the binding tests fire; any other    │
//	│  use is wrong.                                              │
//	│                                                             │
//	│  Binding tests (lifecycle/artifact_access.mutation-audit.yaml): │
//	│    muEnableArtifactCommitmentRequired →                     │
//	│      TestVerifyAndDecryptArtifact_PRE_MissingCommitments    │
//	│    muEnableGrantAuthorizationCheck    →                     │
//	│      TestGrantArtifactAccess_AuthCheck_Binding              │
//	│    muEnableWitnessDeserialize         →                     │
//	│      TestEvaluateArbitration_WitnessDeserializeBinding      │
//	│    muEnableWitnessPositionBinding     →                     │
//	│      TestEvaluateArbitration_WitnessPositionBinding         │
//	│    muEnableWitnessIndependence        →                     │
//	│      TestEvaluateArbitration_WitnessIndependenceBinding     │
//	│    muEnableReconstructSizeCheck       →                     │
//	│      TestReconstructSizeCheck_Binding                       │
//	│                                                             │
//	│  Group 6.3 — CheckGrantAuthorization internal membership:   │
//	│    muEnableGrantAuthoritySetMembership →                    │
//	│      TestCheckGrantAuthorization_AuthoritySetMembership_Binding │
//	│    muEnableAuthorizedRecipientMembership →                  │
//	│      TestCheckGrantAuthorization_AuthorizedRecipientMembership_Binding │
//	└─────────────────────────────────────────────────────────────┘
package lifecycle

// muEnableArtifactCommitmentRequired gates the
// (params.Commitments.Threshold() == 0) check inside
// VerifyAndDecryptArtifact for the EncryptionUmbralPRE branch.
// When true (production), missing commitments surface
// ErrMissingCommitments before any CFrag verification runs.
// When false, the check is bypassed and PRE_DecryptFrags is
// invoked with empty commitments — the primitive's own
// ErrEmptyCommitments still fires, but the lifecycle-layer
// boundary error is lost and admission may surface a different
// or less specific error to operators.
const muEnableArtifactCommitmentRequired = true

// muEnableGrantAuthorizationCheck gates the Phase 1 dispatch in
// GrantArtifactAccess that runs CheckGrantAuthorization when
// SchemaParams.GrantAuthorizationMode != GrantAuthOpen. When
// true (production), restricted/sealed grants only succeed if
// the granter is in the scope authority set and (for sealed
// mode) the recipient is in the authorized list. When false,
// every grant is treated as open mode and key material is
// produced regardless of authorization context — the silent
// authorization-bypass failure mode this gate exists to
// prevent.
const muEnableGrantAuthorizationCheck = true

// muEnableWitnessDeserialize gates the EvaluateArbitration
// witness Gate 1: deserialize errors on the witness cosignature
// envelope are fatal. When false, deserialize errors are
// ignored and a malformed witness cosignature is treated as
// "no witness available", which combined with the supermajority
// check could authorize an override on bogus witness evidence.
const muEnableWitnessDeserialize = true

// muEnableWitnessPositionBinding gates witness Gate 2: the
// witness cosignature MUST reference the RecoveryRequestPos via
// IsCosignatureOf. When false, an attacker-supplied witness
// cosignature on any unrelated entry would be accepted —
// readmitting the BUG-016 cross-position cosignature class at
// the arbitration boundary.
const muEnableWitnessPositionBinding = true

// muEnableWitnessIndependence gates witness Gate 3: the witness
// signer MUST NOT appear in EscrowNodeSet. When false, a
// witness that is itself an escrow node admits, allowing escrow
// nodes to "self-witness" their own override request and defeat
// the independence requirement schema-declared via
// OverrideRequiresIndependentWitness.
const muEnableWitnessIndependence = true

// muEnableReconstructSizeCheck gates the
// (len(keyBytes) != escrow.SecretSize) defensive invariant after
// escrow.Reconstruct returns. When false, a primitive-layer
// contract violation (Reconstruct returning wrong-size bytes)
// silently propagates into RecoveryResult — producing a
// truncated or oversized master-identity key.
const muEnableReconstructSizeCheck = true

// ═════════════════════════════════════════════════════════════════════
// Group 6.3 — CheckGrantAuthorization internal membership gates
// ═════════════════════════════════════════════════════════════════════
//
// Group 6.2 shipped muEnableGrantAuthorizationCheck which gates the
// *dispatch* into CheckGrantAuthorization (whether the function runs
// at all for non-open modes). Group 6.3 extends discipline one layer
// deeper onto the two internal membership checks CheckGrantAuthorization
// performs once it is running:
//
//   1. Authority-set membership. For restricted and sealed modes,
//      scopeEntry.Header.AuthoritySetContains(GranterDID) MUST hold
//      before any key material is produced. Off allows a non-authority
//      granter to bypass scope authorization entirely — the granter
//      check drops out and restricted mode collapses to open mode.
//
//   2. Authorized-recipient membership. For sealed mode, the
//      RecipientDID MUST be in AuthorizedRecipients. Off collapses
//      sealed mode to restricted mode — sealed grants would be issued
//      to any recipient the granter targets, defeating the recipient
//      allowlist the schema encodes.
//
// These gates are load-bearing even though the surrounding flow
// returns Authorized=false on either check failure, because the mutation
// audit runs the switches against the actual enforcement site. If the
// switch is off, the internal check silently passes and the test-bound
// authorization result flips from refused to granted.

// muEnableGrantAuthoritySetMembership gates the
// scopeEntry.Header.AuthoritySetContains(GranterDID) check inside
// CheckGrantAuthorization for restricted and sealed modes. When true
// (production), non-authority granters are refused before any key
// material is produced. When false, the check short-circuits to true
// and every granter passes the scope-authority boundary — restricted
// and sealed modes silently collapse to open-mode semantics.
const muEnableGrantAuthoritySetMembership = true

// muEnableAuthorizedRecipientMembership gates the recipient-in-
// AuthorizedRecipients loop inside CheckGrantAuthorization for sealed
// mode only. When true (production), recipients not in the sealed
// allowlist are refused. When false, the loop short-circuits to true
// and sealed mode silently collapses to restricted mode — the granter
// authority boundary still holds, but the recipient allowlist is no
// longer enforced.
const muEnableAuthorizedRecipientMembership = true
