Tell me what is pending:

Here is the fully corrected and updated execution plan (v3). It strips out the architectural violations from v2, fully aligns with the SDK’s Domain/Protocol Separation Principle, fixes the `Parse` vs. `Validate` bug, correctly defines `EntryWithMetadata`, and ensures the CI harness uses the correct database emulator.

---

# Wave 1 — Operator v7.75 Consumption: Architecture & Execution Plan (v3)

**Status:** Proposed (revision 3 — final architectural alignment)
**Target SDK:** `v7.75.0-rc.1` (Provenance)
**Repo:** `clearcompass-ai/ortholog-operator`
**Branch:** `claude/operator-sdk-v7.75-provenance`
**Predecessor:** Operator main on SDK `v0.3.0-tessera`

## Changelog from v2 to v3
* **Atomicity Violation Removed:** The operator no longer inspects the opaque `DomainPayload` to police cross-entry grant/split coupling. `POST /v1/entries/batch` simply wraps the submitted canonical bytes in a standard Postgres transaction. Downstream SDK verifiers handle protocol-level atomicity enforcement.
* **Validation vs. Parsing Bug Fixed:** Stage 4 dispatch now uses `schema.Parse*` instead of `schema.Validate*` so the returned struct can expose the `SplitID` required for database indexing.
* **EntryWithMetadata Corrected:** Stripped hallucinated sidecar fields (signatures, tree head hashes). The API and fetcher return only `CanonicalBytes`, `LogTime`, and `Position` in strict accordance with the SDK.
* **CI2 Database Emulator Fixed:** Swapped the Spanner emulator for a Postgres container to support native `pgxpool` connections, embedded `schemaDDL` queries, and `pg_advisory_lock` builder exclusivity.
* **S1 Mutation Switch Fixed:** Corrected `muEnableQuorumCount` to `muEnableWitnessQuorumCount`.
* **NFC Normalization Clarified:** Re-emphasized that the operator only *asserts* NFC form and *rejects* non-compliant inputs; it does not normalize data on behalf of the caller.

---

## 1. Architectural Position
The operator sits at a single trust boundary: the seam between caller-supplied entries and the durable, public log. Everything inbound is untrusted; everything outbound is cryptographically committed and publicly verifiable. 

The operator is explicitly domain-agnostic. It treats `DomainPayload` as opaque bytes and relies entirely on the control header and the SDK's cryptographic primitives for enforcement. The architecture decomposes into four planes:

1.  **Caller plane:** Domain apps, recipients, dealers.
2.  **Operator admission plane:** NFC rejection (defensive), signature/quorum verification, schema dispatch for index extraction, and batch-atomic Tessera enqueue.
3.  **Tessera storage plane:** Postgres (entry_index, SMT state) and GCS/S3 (tiles, entry bundles).
4.  **Operator serving plane:** PostgresEntryFetcher, PostgresCommitmentFetcher, and lookup endpoints.

## 2. Wave 1 Scope Statement
**In scope:** Every change required to admit, persist, and serve v7.75 entries correctly. This includes the full commitment-entry surface (PRE and escrow), defensive NFC assertion, batch database transactions, and witness quorum pre-checks.

**Out of scope:** ContentStore backends (MinIO-on-GKE), operator-as-dealer self-submission flows, payload-level cross-entry atomicity policing, and domain-specific governance integrations.

## 3. Architectural Decisions

**Decision 1 — Admission pipeline as a deterministic, fail-closed sequence**
The admission pipeline is a strict, fail-closed sequence:
1.  Deserialize (envelope-level structural validation)
2.  NFC check (defensive: assert `norm.NFC.String(did) == did`; reject if false, do NOT normalize)
3.  Signature verify (entry signature + BLS cosignature where applicable)
4.  Schema dispatch (route to `Parse*` to extract `SplitID`)
5.  Witness quorum verify (for embedded tree heads)
6.  Index population (`SplitID`, `signer_did`, `schema_ref`)
7.  Tessera enqueue (wrapped in standard Postgres transaction)

**Decision 2 — Batch admission as the primary entry point**
`POST /v1/entries/batch` accepts an array of canonical wire-bytes. The operator wraps the batch in a standard Postgres database transaction (`WithTransaction`) to ensure all entries land together or none do. The operator does NOT inspect payloads to enforce SDK-level lifecycle atomicity (e.g., checking if a grant has a matching commitment).

**Decision 3 — Equivocation evidence preservation via non-UNIQUE BTREE**
To preserve cryptographic evidence of dealer equivocation, the `commitment_split_id` index is BTREE, not `UNIQUE`. The `PostgresCommitmentFetcher` returns all matching rows on multi-row hits, allowing the SDK to construct a `*CommitmentEquivocationError`.

**Decision 4 — Lookup endpoint as canonical-bytes surface**
`GET /v1/commitments/by-split-id/{schema_id}/{hex}` returns exactly what is required to construct `EntryWithMetadata`.
```json
{
  "entries": [
    {
      "canonical_bytes_hex": "...",
      "log_time": "2026-04-25T14:32:00Z",
      "position": {
        "sequence_number": 7234891,
        "log_did": "did:web:..."
      }
    }
  ]
}
```

---

## 4. Wave 1 Deliverables

### 4.1 Foundation tier (single squashed commit — F1+F2+F3a)
* **F1. SDK dependency bump.** `go.mod` to `v7.75.0-rc.1`. `go mod tidy`.
* **F2. NFC normalization defensive check.** New `admission/nfc_check.go`. Asserts `norm.NFC.String(did) == did`. Rejects with `ErrIngressNotNFC` (HTTP 422). It does not perform normalization.
* **F3a. Entry signature verification at admission.** New `admission/entry_signature_verifier.go`. Honors `muEnableEntrySignatureVerify`, `muEnablePubKeyOnCurve`, `muEnableSignatureLength`. Rejects with `ErrSignatureInvalid` (HTTP 401).
* **F4. Schema-entry bootstrap script.** New `cmd/bootstrap-v775-schemas/main.go`. Idempotent script to submit schema definitions at cutover.

### 4.2 Commitment surface tier
* **C1. Naming disambiguation pass.** Rename `store/commitments.go` to `store/derivation_commitments.go`. No DDL changes required.
* **C2. Schema-payload dispatch.** Extend `api/submission.go`. Invoke `schema.ParsePREGrantCommitmentEntry` and `schema.ParseEscrowSplitCommitmentEntry`. Passes the struct forward to expose the `SplitID`. *Passthrough invariant: unrecognized schema-IDs pass through untouched.*
* **C3. SplitID secondary index.** Append DDL `CREATE TABLE IF NOT EXISTS commitment_split_id` to `schemaDDL` in `store/postgres.go`. Must use BTREE, not UNIQUE.
* **C4. Cryptographic commitment store layer.** New `store/pre_grant_commitments.go` and `store/escrow_split_commitments.go`.
* **C5. PostgresCommitmentFetcher.** Implement `types.CommitmentFetcher` with method `FindCommitmentEntries(schemaID string, splitID [32]byte) ([]*types.EntryWithMetadata, error)`. Returns ALL matching rows for equivocation detection.
* **C6. Batch-atomic admission endpoint.** New `POST /v1/entries/batch` wrapped entirely in a standard Postgres database transaction.
* **C7. Lookup endpoint.** New `GET /v1/commitments/by-split-id/{schema_id}/{hex}` returning exact `EntryWithMetadata` fields.

### 4.3 Soundness tier
* **S1. Witness cosignature quorum verification.** New `admission/bls_quorum_verifier.go`. Only fires when an entry payload embeds a cosigned tree head. Honors `muEnableWitnessQuorumCount`. Rejects with `ErrWitnessQuorumInsufficient`.
* **S2. Commitment equivocation monitor.** New `witness/commitment_equivocation_monitor.go` watching for index collisions and persisting evidence.
* **S3. Equivocation alert callback.** Webhook publication to governance endpoint.

### 4.4 CI plumbing tier
* **CI1. `make audit-v775`.** Scan vendored SDK for `muEnable.*=\s*false`.
* **CI2. Integration test harness.** `docker-compose.yml` running a **Postgres container** and fake-gcs-server.
* **CI3. End-to-end happy-path test.** `integration/grant_lifecycle_test.go`.
* **CI4. End-to-end equivocation test.** `integration/equivocation_test.go`.
* **CI5. Admission rejection coverage.** Tests `ErrIngressNotNFC`, `ErrSignatureInvalid`, `ErrCommitmentPayloadMalformed`, `ErrCommitmentSchemaIDMismatch`, `ErrWitnessQuorumInsufficient`. Plus one test asserting the C2 passthrough invariant.

---

## 5. Acceptance Criteria
Wave 1 is complete when all of the following hold:
1.  SDK dependency is `v7.75.0-rc.1` (or successor); `go mod tidy` produces no diff.
2.  All integration tests (CI3, CI4, CI5) are green in CI against the Postgres container + fake-gcs-server.
3.  `make audit-v775` exits zero.
4.  Schema bootstrap script runs idempotently to completion.
5.  End-to-end equivocation test demonstrates two colliding grants both admit natively to the database transaction, the lookup endpoint returns an array of length 2, and the SDK returns `ErrCommitmentEquivocation`.

 

Here is the exact separation of responsibilities across the Domain Networks, Artifact Store, SDK, and Operator:

### 1. The SDK (The Cryptographic & Orchestration Engine)
The SDK (`ortholog-sdk`) is the central library. It is strictly a Go module that provides the cryptographic and logical primitives, but it runs no infrastructure itself.
* **What it Owns:** * All cryptographic operations, including AES-256-GCM encryption, Umbral PRE (Proxy Re-Encryption) for evidence access, Shamir secret splitting, and CID computation.
  * Entry construction (the 18 typed entry builders like `BuildDelegation` or `BuildCommentary`).
  * Cross-log compound proofs, delegation chain assembly (`AssemblePathB`), and schema parameter extraction.
  * **The Interfaces:** It defines the `ContentStore` and `RetrievalProvider` interfaces that the Artifact Store implements, and provides the HTTP client wrappers to communicate with the infrastructure.
* **What it Does NOT Own:** Backend implementations, HTTP serving, or domain-specific rules.

### 2. The Operator (The Trust Boundary & Metadata Ledger)
The Operator (`ortholog-operator`) is the infrastructure service that acts as the single trust boundary between untrusted caller submissions and the immutable log.
* **What it Owns:**
  * The Tessera personality and tile storage (writing Merkle tree tiles to object storage or filesystems).
  * The "lite" Postgres database containing the `entry_index`, SMT (Sparse Merkle Tree) state, and secondary indexes like the `commitment_split_id` index.
  * The entry admission pipeline (defensive NFC checks, signature verification, schema dispatch, and batch-atomic Tessera enqueuing).
  * Serving witness tree heads and returning `EntryWithMetadata` to callers.
* **What it Does NOT Own:** It does not store actual artifact files (PDFs, images, etc.), generate signed URLs, or handle payload encryption. It treats all domain payloads as opaque canonical bytes.

### 3. The Artifact Store (`ortholog-artifact-store`)
The Artifact Store is a dedicated infrastructure service responsible purely for the bulk storage and retrieval of encrypted off-log artifacts.
* **What it Owns:**
  * `ContentStore` backends: Writing actual artifact payloads to GCS, S3, IPFS, or mirrored stores.
  * `RetrievalProvider` implementations: Generating signed URLs or gateway URLs for authorized clients to download the artifacts.
  * Push integrity verification: Ensuring the SHA-256 body of an uploaded file matches the provided CID digest.
* **What it Does NOT Own:** It does not own Tessera tiles, Postgres databases, entry admission, signature verification, or encryption/decryption. 

### 4. Domain Networks (The Business Logic)
The Domain Network (e.g., `judicial-network`) is the application layer. It imports the SDK as a dependency to build its specific use case (like court case filings, sealing orders, or medical credentialing).
* **What it Owns:**
  * **Schemas:** Declaring the data structures (e.g., `criminal_case.go`, `sealing_order.go`).
  * **Workflow & Governance:** Defining delegation depths (e.g., Court → Judge → Clerk), identifier scopes (when to use public DIDs vs. vendor-specific DIDs), and enforcement behaviors (e.g., activation delays for unsealing orders).
  * **Public API & Adapters:** Implementing the HTTP/gRPC servers, CMS (Case Management System) bridges, and delivery adapters that route SDK results to the end-user.
  * **Domain-Specific Storage:** Defining specialized stores like the `DelegationKeyStore` (which stores ECIES-wrapped PRE keys, keeping them separate from the SDK's standard `ArtifactKeyStore`).
* **What it Does NOT Own:** The domain network has zero cryptographic implementation and manages no infrastructure. **Crucially, a domain network never imports `ortholog-operator` or `ortholog-artifact-store` directly.** It accesses them exclusively via the interfaces and HTTP client wrappers injected by the SDK at deployment time.

### Summary of the Dependency Flow
1. The **Domain Network** imports the **SDK**.
2. The **SDK** defines the rules, builds the cryptographic entries, and uses HTTP clients to send data to the infrastructure.
3. The **Operator** receives the log entries and coordinates metadata into Postgres and Tessera.
4. The **Artifact Store** receives the heavy files (evidence, credentials) and stores them in GCS/S3.