package types

import "time"

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

// SchemaParameters holds domain-visible parameters extracted from a schema's
// Domain Payload. Pure data type — no extraction logic here.
//
// The SchemaParameterExtractor interface (schema/parameters.go) produces this.
// Default JSON extractor implemented in Phase 4 (first consumer).
// Domain repos provide custom extractors for non-JSON payloads.
//
// Consumed by:
//   - Phase 4 verifier: key_rotation reads MaturationEpoch,
//     contest_override reads OverrideRequiresIndependentWitness,
//     schema_succession reads MigrationPolicy and PredecessorSchema
//   - Phase 5 condition_evaluator: reads ActivationDelay and CosignatureThreshold
//   - Phase 5 exchange/lifecycle/artifact_access.go: reads ArtifactEncryption,
//     GrantEntryRequired, ReEncryptionThreshold
//   - Phase 6 exchange/lifecycle/artifact_access.go: reads GrantAuthorizationMode,
//     GrantRequiresAuditEntry
//
// Builder NEVER reads the operational fields (SDK-D6).
// One struct for now, split at 15 fields.
type SchemaParameters struct {
	// ── Protocol-mechanical (verifier + condition_evaluator) ──────────

	ActivationDelay                    time.Duration
	CosignatureThreshold               int
	MaturationEpoch                    time.Duration
	CredentialValidityPeriod           *time.Duration      // nil = no expiry
	OverrideRequiresIndependentWitness bool
	MigrationPolicy                    MigrationPolicyType
	PredecessorSchema                  *LogPosition        // nil = no predecessor

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
}
