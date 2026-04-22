# ADR-001: The Four-Part Legitimacy Test for ControlHeader Fields

**Status:** Accepted (v7.5)
**Supersedes:** —
**Related:** ADR-002 (BuildSchemaEntry structured parameters), ADR-004 (Zero-trust scope resolution)

## Context

Pre-v7.5 `ControlHeader` had accreted four fields (`AuthoritySkip`,
`AuthorityDID`, `KeyGenerationMode`, `CommutativeOperations`) that
each failed at least one test of architectural legitimacy. Some were
self-declared security claims with no cryptographic binding. Some
were pure write-only wire ballast with no reader. Some were
schema-level parameters that had leaked into the per-entry header.

The pattern — speculative fields added in anticipation of consumers
that never materialised or never obtained the ability to validate
them — is a canonical anti-pattern in wire-protocol design. Every
such field is a future attack surface (parsers must handle it,
attackers can smuggle values through it) with no corresponding
security benefit.

## Decision

A field belongs in `ControlHeader` **if and only if all four** hold:

1. **SDK reads it.** Code acts on the value. Otherwise the field is
   dead or — worse — a trap for downstream consumers who assume the
   SDK validated what they see.
2. **SDK validates it.** Structural, cryptographic, or derivational
   — but validated against a ground truth, not taken on the signer's
   word.
3. **Signer has authority to make the claim.** `SignerDID` passes
   trivially (the signer controls their own DID). `PriorAuthority`
   passes because the signer is asserting what they observed at
   signing time. Claims about anything external to the signing
   action fail.
4. **No better location exists.** Domain-specific parameters belong
   in `DomainPayload`. Attestations about other entities belong in
   separate signed entries.

This rubric governs every future field proposal. A proposal that
fails any of the four is rejected, not relaxed.

## Consequences

**Removed in v7.5 under this rule:**

| Field | Failed test |
| --- | --- |
| `AuthoritySkip` | #2 (unvalidatable — "trust me, I validated the intermediate") |
| `AuthorityDID` | #1 and #2 (no reader; no cryptographic binding to the amendment delta) |
| `KeyGenerationMode` | #3 (self-declared security claim; keys cannot attest their own origin) |
| `CommutativeOperations` | #4 (schema-level parameter; belongs in DomainPayload per SchemaParameters) |

**Rejected under this rule:**

Future proposals like `KeyRotationAllowed`, `RevocationWindow`,
`CustodyClaim`, `AttestationVersion`, `TrustLevel` — any field whose
trust story is "the signer declares X about themselves" — are
rejected without further discussion. Claims requiring trust go
through separate signed entries whose authority is evaluable (see
`docs/attestation-entries.md`).

## Wire format consequence

v6 → v7 is a breaking wire-format bump. The four-field removal is
not backward-compatible; v6 bytes are rejected with
`ErrUnknownVersion`. This is the designed hard-cut discipline in
`version_policy.go`: pre-production systems with no v6 data pay no
migration cost, and future systems inherit a leaner header that
every remaining field earns its place in.
