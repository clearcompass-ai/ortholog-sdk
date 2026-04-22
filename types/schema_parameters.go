package types

import (
	"math"
	"time"
)

// MigrationPolicyType declares how schema succession is evaluated.
type MigrationPolicyType uint8

const (
	MigrationStrict    MigrationPolicyType = 1 // No backward compatibility
	MigrationForward   MigrationPolicyType = 2 // Forward migration only
	MigrationAmendment MigrationPolicyType = 3 // Amendment-based migration
)

// EncryptionScheme selects the artifact access control model.
// AES-256-GCM is ALWAYS storage encryption (permanent). This field selects
// the ACCESS CONTROL model on top.
//
//   - EncryptionAESGCM: exchange-mediated re-encryption (exchange sees plaintext
//     during re-encryption). Default for existing schemas.
//   - EncryptionUmbralPRE: M-of-N threshold proxy re-encryption with DLEQ proofs.
//     Exchange never sees plaintext.
//
// Builder NEVER reads this field (SDK-D6).
type EncryptionScheme int

const (
	EncryptionAESGCM    EncryptionScheme = iota // default
	EncryptionUmbralPRE                         // threshold PRE
)

// ThresholdConfig specifies M-of-N parameters for threshold operations.
// Used by ReEncryptionThreshold: same M-of-N escrow nodes as Shamir.
// nil for aes_gcm schemas.
type ThresholdConfig struct {
	M int
	N int
}

// ─────────────────────────────────────────────────────────────────────
// Grant authorization policy
// ─────────────────────────────────────────────────────────────────────
//
// GrantAuthorizationMode controls who may authorize artifact access grants
// and who may receive them. This is ACCESS CONTROL POLICY on the grant
// operation — not selective disclosure in the credentialing sense (ZKP
// field revelation via BBS+ or SD-JWT). The naming is deliberate.
//
// The SDK enforces the mode. The domain application provides the inputs:
//   - The granter's DID (who is calling GrantArtifactAccess)
//   - The scope pointer (which scope governs the entity)
//   - The authorized recipients list (which DIDs may receive access)
//
// The SDK does not know what domain it is operating in. It checks
// structural membership (granter in authority set, recipient in list)
// and produces or withholds key material. The same code path serves
// physician credentialing (doctor discloses rotation to a medical board),
// judicial networks (clerk grants sealed evidence to defense counsel),
// and any future domain.
//
// Follows the same typed-enum pattern as EncryptionScheme and
// MigrationPolicyType. uint8 ensures exhaustive switch coverage by
// the compiler and prevents string typos ("Sealed" vs "sealed").
//
// Default zero value = GrantAuthOpen = no authorization check = backward
// compatible with every schema that predates this field.

type GrantAuthorizationMode uint8

const (
	// GrantAuthOpen: any grant request is honored. No authorization check
	// is performed. The SDK produces key material for any requester.
	//
	// This is the default (zero value). Every existing schema that does
	// not declare grant_authorization_mode behaves as GrantAuthOpen.
	// No existing tests or behaviors change.
	GrantAuthOpen GrantAuthorizationMode = 0

	// GrantAuthRestricted: the granter must be a member of the scope's
	// AuthoritySet. The SDK fetches the scope entry, reads AuthoritySet,
	// and checks membership. If the granter is not in the set, the SDK
	// refuses to produce key material — no ECIES wrapping, no KFrag
	// generation, no retrieval credential.
	//
	// Use case: the schema says "only scope authority members may grant
	// artifact access." In physician credentialing, this means only
	// authorized institutional officials (under delegation) can grant
	// access to protected artifacts. In judicial networks, only court
	// officers in the scope's authority set can grant evidence access.
	GrantAuthRestricted GrantAuthorizationMode = 1

	// GrantAuthSealed: restricted check PLUS the recipient's DID must
	// appear in the caller-provided authorized recipients list.
	//
	// TRUST BOUNDARY: The SDK enforces membership in the list. The
	// domain application is responsible for the list's correctness.
	// In judicial networks, the list originates from a sealing order's
	// Domain Payload, parsed by the judicial network's domain code.
	// In physician credentialing, the list originates from the holder's
	// consent decision, mediated by the exchange. The SDK cannot verify
	// that the list matches the originating entry because the SDK does
	// not read Domain Payload (SDK-D6). An incorrect list is a domain
	// bug, not a protocol violation.
	//
	// Same caller-provides-SDK-validates pattern as:
	//   - CosignaturePositions in EvaluateConditions (condition_evaluator.go)
	//   - CandidatePositions in AssemblePathB (assemble_path_b.go)
	//   - KnownDelegations in WalkDelegationTree (delegation_tree.go)
	GrantAuthSealed GrantAuthorizationMode = 2
)

// ─────────────────────────────────────────────────────────────────────
// Override threshold rule (Wave 2)
// ─────────────────────────────────────────────────────────────────────
//
// OverrideThresholdRule declares how many authorities must approve an
// override of a contested operation (scope enforcement, escrow recovery
// arbitration). Read from the governing schema's Domain Payload via
// SchemaParameterExtractor.
//
// Before Wave 2, the SDK hardcoded ⌈2N/3⌉ in verifier/contest_override.go
// and lifecycle/recovery.go. Domains that wanted different override
// thresholds (simple majority for low-stakes logs, unanimity for
// high-stakes sealed evidence) had no way to express it. This enum
// makes the threshold schema-declared and preserves ⌈2N/3⌉ as the
// default (zero value) for backward compatibility.
//
// Same typed-enum pattern as EncryptionScheme, MigrationPolicyType,
// and GrantAuthorizationMode.

type OverrideThresholdRule uint8

const (
	// ThresholdTwoThirdsMajority: ⌈2N/3⌉ approvals required.
	// SDK default (zero value). Matches pre-Wave-2 behavior.
	ThresholdTwoThirdsMajority OverrideThresholdRule = 0

	// ThresholdSimpleMajority: ⌈N/2⌉ + 1 approvals required.
	// Appropriate for low-stakes enforcement where blocking a minority
	// veto matters more than requiring broad consensus.
	ThresholdSimpleMajority OverrideThresholdRule = 1

	// ThresholdUnanimity: all N authorities must approve.
	// Appropriate for high-stakes operations (sealed evidence access,
	// escrow recovery for large credentialing records) where any single
	// authority's dissent should block.
	ThresholdUnanimity OverrideThresholdRule = 2
)

// RequiredApprovals returns the number of approvals needed under this
// rule for an authority set of size n. Single source of truth — both
// verifier/contest_override.go and lifecycle/recovery.go call this
// method so the math cannot drift between call sites.
//
// Edge cases:
//   - n <= 0: returns 0 (no authorities, nothing to approve).
//   - ThresholdSimpleMajority with n == 1: returns 1 (trivially unanimous).
//   - Unknown rule: falls back to the two-thirds default, which is the
//     conservative choice for operators that upgrade the SDK before
//     updating their schema payloads.
func (r OverrideThresholdRule) RequiredApprovals(n int) int {
	if n <= 0 {
		return 0
	}
	switch r {
	case ThresholdSimpleMajority:
		return n/2 + 1
	case ThresholdUnanimity:
		return n
	default: // ThresholdTwoThirdsMajority + any unknown value
		return int(math.Ceil(2.0 * float64(n) / 3.0))
	}
}

// String returns the canonical snake_case label for a threshold rule.
// Used in operator logs (e.g., ArbitrationResult.Reason) so readers
// can identify the policy in effect without mapping integers to names.
//
// The string values match the JSON enum parsed by
// schema.JSONParameterExtractor's override_threshold field, so a rule
// round-trips cleanly: schema JSON → typed enum → log message → schema JSON.
//
// Unknown rules render as "two_thirds" to match the fallback in
// RequiredApprovals. The two methods stay consistent: any value that
// behaves as two-thirds in the math also prints as two-thirds in logs.
func (r OverrideThresholdRule) String() string {
	switch r {
	case ThresholdSimpleMajority:
		return "simple_majority"
	case ThresholdUnanimity:
		return "unanimity"
	default: // ThresholdTwoThirdsMajority + any unknown value
		return "two_thirds"
	}
}

// SchemaParameters holds domain-visible parameters extracted from a schema's
// Domain Payload. Pure data type — no extraction logic here.
//
// The SchemaParameterExtractor interface (schema/parameters.go) produces this.
// Default JSON extractor implemented in Phase 4 (first consumer).
// Domain repos provide custom extractors for non-JSON payloads.
//
// Consumed by:
//   - Phase 4 verifier: key_rotation reads MaturationEpoch,
//     contest_override reads OverrideRequiresIndependentWitness
//     and OverrideThreshold, schema_succession reads MigrationPolicy
//     and PredecessorSchema
//   - Phase 5 condition_evaluator: reads ActivationDelay and CosignatureThreshold
//   - Phase 5 exchange/lifecycle/artifact_access.go: reads ArtifactEncryption,
//     GrantEntryRequired, ReEncryptionThreshold
//   - Phase 6 exchange/lifecycle/artifact_access.go: reads GrantAuthorizationMode,
//     GrantRequiresAuditEntry
//   - Wave 2 verifier/contest_override.go + lifecycle/recovery.go:
//     reads OverrideThreshold
//
// Builder NEVER reads the operational fields (SDK-D6).
type SchemaParameters struct {
	// ── Protocol-mechanical (verifier + condition_evaluator) ──────────

	ActivationDelay                    time.Duration
	CosignatureThreshold               int
	MaturationEpoch                    time.Duration
	CredentialValidityPeriod           *time.Duration // nil = no expiry
	OverrideRequiresIndependentWitness bool
	MigrationPolicy                    MigrationPolicyType
	PredecessorSchema                  *LogPosition // nil = no predecessor

	// OverrideThreshold declares the supermajority rule for contest
	// overrides and escrow arbitration. Zero value = ThresholdTwoThirdsMajority
	// (⌈2N/3⌉, the SDK default preserving pre-Wave-2 behavior).
	//
	// Consumed by:
	//   - verifier/contest_override.go EvaluateContest
	//   - lifecycle/recovery.go EvaluateArbitration
	OverrideThreshold OverrideThresholdRule

	// ── Operational — artifact access control ─────────────────────────
	// (exchange + domain, never builder or verifier)

	ArtifactEncryption    EncryptionScheme // aes_gcm | umbral_pre
	GrantEntryRequired    bool             // true -> publish grant commentary entries
	ReEncryptionThreshold *ThresholdConfig // nil for aes_gcm. Same M-of-N as Shamir.

	// ── Operational — grant authorization ─────────────────────────────
	// (exchange + domain, never builder or verifier)
	//
	// These two fields control WHO may call GrantArtifactAccess and WHO
	// may receive the resulting key material. They compose with the
	// artifact encryption fields above — GrantAuthorizationMode gates
	// the decision, ArtifactEncryption determines the mechanism.
	//
	// Added in Phase 6. Default zero values preserve all existing behavior:
	// GrantAuthOpen (0) = no check, GrantRequiresAuditEntry false = no
	// forced audit entry. Every pre-Phase-6 schema continues to work
	// identically.

	// GrantAuthorizationMode selects the grant authorization policy.
	// See the GrantAuthorizationMode type definition for semantics.
	// Default: GrantAuthOpen (no restriction, backward compatible).
	GrantAuthorizationMode GrantAuthorizationMode

	// GrantRequiresAuditEntry forces a commentary entry for every grant
	// under restricted or sealed mode. Separate from GrantEntryRequired
	// because the two fields serve different purposes:
	//
	//   GrantEntryRequired:      "record that a grant happened" (any mode)
	//   GrantRequiresAuditEntry: "record that an AUTHORIZED grant happened"
	//                            (restricted/sealed modes only)
	//
	// When true, GrantArtifactAccess always produces a GrantEntry in its
	// result, regardless of GrantEntryRequired. The caller (exchange) is
	// responsible for submitting the entry to the log. The SDK builds
	// the entry; the exchange submits it.
	GrantRequiresAuditEntry bool

	// ── Concurrency (schema-level OCC mode) ──────────────────────────
	//
	// CommutativeOperations declares the domain-interpreted operation
	// tags that commute under Δ-window CRDT resolution. Non-empty
	// enables commutative OCC for every Path C enforcement against
	// this schema; empty selects strict OCC (Decision 37 default).
	//
	// Moved from ControlHeader to SchemaParameters in v7.5 to restore
	// the protocol/domain separation boundary: commutativity is a
	// schema property, not per-entry wire metadata. Callers set the
	// field on the schema entry's SchemaParameters before building;
	// builder.BuildSchemaEntry marshals it into Domain Payload;
	// schema.JSONParameterExtractor reads it on the verifier side.
	//
	// Invariant after Extract: always a non-nil slice. Absent JSON
	// field, explicit JSON null, and explicit empty JSON array all
	// normalize to an empty []uint32. Callers can test `len(v) == 0`
	// without nil-checking.
	CommutativeOperations []uint32
}
