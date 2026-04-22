# Attestation Entries — Domain Pattern

**Status:** Domain guidance for v7.5 and later.
**Context:** v7.5 removed `KeyGenerationMode` (and the whole `KeyGenMode`
type) from `ControlHeader` because a key cannot attest its own origin
(ADR-001). This document describes the pattern domain implementers
use for the functionality `KeyGenerationMode` claimed to provide.

## The problem

Some domains care about key provenance:

- Judicial networks: sovereign user-held keys grant different legal
  standing than custodial exchange-held keys.
- Medical credentialing: client-side enclave keys meet HIPAA-style
  sole-control requirements; custodial keys do not.
- Regulated financial custody: the distinction is literally the
  regulatory boundary.

Pre-v7.5, `ControlHeader.KeyGenerationMode` tried to declare this
per-entity. It was self-declared: a compromised exchange could mint
root entities whose headers claimed `KeyGenClientSideBlind` while
the exchange held the signing key custodially. Downstream
verifiers trusting the field would grant stronger guarantees to
exactly the attacker's entries — the canonical anti-pattern in
protocol review.

## The pattern

A key's provenance is a claim made by the institution that
witnessed the generation, not by the entity holding the key.
Provenance therefore belongs in a **separate signed entry**,
authored by the exchange's institutional key, attesting the
generation mode for a named entity at a named position.

```
(root entity entry)         Position P1, signed by Alice
    ↑ references
(key attestation entry)     Position P2, signed by Exchange_X,
                            SubjectIdentifier = Alice's DID,
                            Domain Payload declares:
                              {
                                "attested_entity": "did:web:alice",
                                "attested_entity_position": P1,
                                "generation_mode": "client_side_enclave",
                                "attestation_time": 1_700_000_000,
                                "witness_artifact_hash": ...
                              }
```

Properties the pattern provides that the removed header field did
not:

1. **Verifiable.** The claim is signed by `Exchange_X`'s
   institutional key. A verifier evaluating the claim knows whose
   reputation is staked.
2. **Revocable.** If the exchange learns the generation was
   misrepresented, it publishes a correcting attestation. The log
   preserves both, and the Decision 52 scope-history walk resolves
   authority at the time the downstream action was taken.
3. **Separable.** Domains that do not care about generation-mode
   provenance simply do not publish attestation entries. Zero
   overhead for the common case.
4. **Composable.** Multiple attestations can cover the same entity
   at different times (rotation, multi-party witnessing,
   independent-witness requirements per
   `SchemaParameters.OverrideRequiresIndependentWitness`).

## Schema shape

The SDK is payload-agnostic. Domain schemas define the attestation
payload shape. A reference shape for the judicial network:

```json
{
  "attested_entity":          "<DID>",
  "attested_entity_position": { "log_did": "...", "sequence": N },
  "generation_mode":          "exchange_managed | client_side_enclave",
  "attestation_time":         <unix-seconds>,
  "witness_artifact_hash":    "<hex bytes>",
  "enclave_platform":         "apple_secure_enclave | android_strongbox | hsm_fips_140_3",
  "attestation_evidence":     "<opaque blob understood by the schema's verifier>"
}
```

A schema author extending this shape should:

- Require `attested_entity` + `attested_entity_position` as a
  (DID, LogPosition) tuple so the attestation is pinned to a
  specific entry, not a DID alone.
- Declare the set of allowed `generation_mode` values as enum
  strings and reject any other value at payload-parse time.
- Define `witness_artifact_hash` / `attestation_evidence` semantics
  per the platform (Apple App Attest, Android Key Attestation, HSM
  quote, etc.).
- Declare in the schema whether attestation is required before an
  entity's entries count for cosignature thresholds etc.

## Entry-type shape

Attestation entries are Path A entries (same-signer amendments
don't apply — the attester is an external exchange). Concretely:

- `AuthorityPath = AuthoritySameSigner` (the exchange attests on
  its own authority).
- `Destination` = the target log's destination DID.
- `SignerDID` = the exchange's institutional DID.
- `SchemaRef` = the attestation schema's position.
- `SubjectIdentifier` = the attested entity's DID (lets operator
  indices answer "what attestations exist for DID X?").
- `DomainPayload` = the JSON shape described above.

No new builder needed. The existing Path A builders cover it.

## Verifier surface

Domains that care read the attestation via
`OperatorQueryAPI.QueryBySubjectIdentifier(entity_did)` + schema-
specific payload parse. The SDK does not make a verdict — it
surfaces the entries; the domain decides how to weigh them.

A domain-specific `VerifyAttestation(entity DID, at LogPosition)`
flow typically:

1. Query attestations for `entity` ordered by admission time.
2. Resolve the latest attestation whose admission position ≤ `at`
   (Decision 52-consistent: authorisations valid at the action's
   signing time).
3. Check the exchange that signed that attestation is in the
   domain's trusted-exchange list at position `at` (same primitive,
   different scope).
4. Parse the payload, apply domain rules.

Steps (1)+(2)+(3) are all instances of `AuthorizedSetAtPosition`-
style queries — the same time-indexed semantics Decision 52
established for scope-authority resolution, applied to a different
scope (the trusted-exchange scope).

## Why not restore the header field

Every compliance pattern for key provenance has an institutional
witness somewhere: an attestation server, a platform TEE, an HSM
quote, a regulator audit. That institutional witness IS the trust
boundary. Promoting its signature to a dedicated entry (with its
own revocability and time-indexing) is architecturally cleaner than
embedding a self-declaration in the entity's own header — which is
why v7.5 removed the header field outright rather than add a
parallel "but really this time it's signed" variant.

If a future proposal wants a header-level claim backed by an
institutional signature, it fails ADR-001's test #3 (the entity
signing the entry is not the authority making the institutional
claim) and should be rejected in favour of this pattern.
