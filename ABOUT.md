# The Ortholog SDK

A complete reference for the `github.com/clearcompass-ai/ortholog-sdk` Go module.

---

## Reading paths

This document serves three audiences. Each can skip sections the others need.

**Domain network builder** — you want to use Ortholog as the substrate for a credentialing, governance, or recordkeeping system. Read Parts I, II, V, VI, VI.5, the first half of VII. Skim VIII. You can skip Part III (the builder internals) and most of XI unless you hit trouble.

**Operator implementer** — you want to run a log-and-builder backed by this SDK. Read Parts I, II, III, VIII, IX, and XI in full. Skim IV and VII. You can skip VI.5.

**Verifier author** — you want to consume entries produced by operators and prove things about them. Read Parts I, II, VII, VIII. Skim III (you need to understand what the builder accepts, not implement it). Section XI.52 (determinism) matters to you more than it does to the other two audiences.

All three should read Part XI before shipping anything.

---

## Table of contents

**Part I — Orientation**
1. [What Ortholog is](#1-what-ortholog-is)
2. [What the SDK is and isn't](#2-what-the-sdk-is-and-isnt)
3. [Architecture and package layout](#3-architecture-and-package-layout)
4. [The seven things every consumer must know](#4-the-seven-things-every-consumer-must-know)

**Part II — Core Protocol Primitives**

5. [The entry envelope (`core/envelope`)](#5-the-entry-envelope-coreenvelope)
6. [The sparse Merkle tree (`core/smt`)](#6-the-sparse-merkle-tree-coresmt)
7. [Shared types (`types/`)](#7-shared-types-types)
8. [Content-addressed storage (`storage/`)](#8-content-addressed-storage-storage)

**Part III — The Builder**

9. [Builder pipeline and path routing](#9-builder-pipeline-and-path-routing)
10. [Concurrency and optimization invariants](#10-concurrency-and-optimization-invariants)
11. [Builder internals reference](#11-builder-internals-reference)

**Part IV — Cryptography**

12. [Canonical hashing (`crypto/hash`)](#12-canonical-hashing-cryptohash)
13. [Signatures (`crypto/signatures`)](#13-signatures-cryptosignatures)
14. [Artifact encryption (`crypto/artifact`)](#14-artifact-encryption-cryptoartifact)
15. [Key escrow (`crypto/escrow`)](#15-key-escrow-cryptoescrow)
16. [Mode B admission (`crypto/admission`)](#16-mode-b-admission-cryptoadmission)

**Part V — Identity and Schema**

17. [DID resolution (`did/`)](#17-did-resolution-did)
18. [Schema parameters (`schema/`)](#18-schema-parameters-schema)

**Part VI — Lifecycle Orchestration**

19. [The universal three-phase pattern](#19-the-universal-three-phase-pattern)
20. [The six lifecycle operations](#20-the-six-lifecycle-operations)

**Part VI.5 — Building a Domain Network on Ortholog**

21. [The shape of a domain network](#21-the-shape-of-a-domain-network)
22. [Worked example: a professional licensing board](#22-worked-example-a-professional-licensing-board)

**Part VII — Verification**

23. [The 90% case: reading entity state](#23-the-90-case-reading-entity-state)
24. [Advanced verification](#24-advanced-verification)

**Part VIII — Witness Infrastructure**

25. [Witness verification](#25-witness-verification)
26. [Operational witness properties](#26-operational-witness-properties)

**Part IX — Integration Boundaries**

27. [The injection contracts](#27-the-injection-contracts)
28. [Vendor DID mapping with double-blind escrow](#28-vendor-did-mapping-with-double-blind-escrow)

**Part XI — Cross-Cutting Concerns**

29. [Domain / protocol separation](#29-domain--protocol-separation)
30. [Determinism requirements](#30-determinism-requirements)
31. [Error taxonomy and HTTP dispatch](#31-error-taxonomy-and-http-dispatch)
32. [Thread safety](#32-thread-safety)

**Appendices**

- [A. File-by-file index](#a-file-by-file-index)
- [C. Glossary](#c-glossary)
- [D. Known limitations](#d-known-limitations)

---

# Part I — Orientation

## 1. What Ortholog is

Ortholog is a protocol for recording signed facts in append-only logs, in a way that lets independent parties verify what happened without trusting any single custodian. The protocol defines how entries are shaped, how state is resolved from a stream of entries, how authority is established, and how logs anchor each other across organizational boundaries.

The protocol has two data structures: the log (an append-only Merkle tree of entries) and the SMT (a sparse Merkle tree that resolves the current state of every entity the log knows about). Everything else — credentials, delegations, scope governance, enforcement actions, cross-log anchors, witness cosignatures — is either an entry on a log, a schema describing how to interpret those entries, or a piece of off-log infrastructure that serves one of those two data structures.

The protocol is intentionally thin. It provides five operations on state (same-signer amendment, delegated amendment, scope-authority enforcement, commentary, new root entity) and three lifecycle phases (publish, condition, activate). Every meaningful change in the system is expressible as a sequence of entries that route through those five operations and pass through those three phases.

What the protocol does *not* provide: domain vocabulary. Ortholog does not know what a credential is, what a license means, what a court order compels, or what an insurance policy covers. Domain meaning lives in Domain Payloads and in the schemas that describe them. The protocol moves signed bytes through a log and resolves state deterministically; a credentialing network, a judicial network, a records registry, or a professional licensing board builds its own meaning on top.

## 2. What the SDK is and isn't

The SDK is a Go module at `github.com/clearcompass-ai/ortholog-sdk`. It implements the protocol's data structures, cryptographic primitives, state-resolution algorithms, verification routines, and lifecycle orchestration. It is transport-agnostic by default — it does not own HTTP endpoints, database schemas, or wire protocols above the entry envelope — but it ships reference HTTP adapters for consumers who want to talk to operators over the REST conventions that `ortholog-operator` and `ortholog-artifact-store` implement.

The SDK is **not**:

- **An operator.** The operator (separate repo: `ortholog-operator`) runs the admission pipeline, persists entries to Postgres and Tessera, serves the REST API, and drives the builder loop. The SDK provides the builder, the entry validator, and the types the operator consumes; it does not provide the operator.
- **An artifact store.** The artifact store (separate repo: `ortholog-artifact-store`) handles content-addressed blob persistence, signed-URL generation, and pinning. The SDK provides CIDs, the `storage.ContentStore` interface, and an HTTP client for that interface; it does not provide the store.
- **A domain application.** The SDK ships no judicial logic, no credentialing logic, no licensing logic. What it ships is the substrate those applications are built on.

This three-way split — SDK, operator, artifact store — is the production topology. In local development and tests, the SDK's in-memory implementations of every boundary (in-memory leaf store, in-memory content store, mock fetcher) let you run the protocol end-to-end without either of the other services.

## 3. Architecture and package layout

The SDK is organized around the five protocol layers. Moving outward from the protocol's cryptographic core:

```
┌─────────────────────────────────────────────────────────────┐
│  lifecycle/     verifier/     witness/                       │
│  (orchestration) (state read) (cosignatures)                 │
│                                                              │
│          ↕                    ↕                              │
│                                                              │
│  builder/       schema/       did/                           │
│  (state write)  (parameters)  (identity resolution)          │
│                                                              │
│          ↕                    ↕                              │
│                                                              │
│  core/envelope  core/smt      storage/     monitoring/       │
│  (wire format)  (state tree)  (blobs)      (alerts)          │
│                                                              │
│          ↕                    ↕                              │
│                                                              │
│  crypto/hash    crypto/signatures    crypto/artifact         │
│  crypto/escrow  crypto/admission                             │
│  types/         log/                                         │
└─────────────────────────────────────────────────────────────┘
```

Dependencies flow downward only. `crypto/*` and `types/` depend on nothing SDK-internal. `core/envelope` and `core/smt` depend on `types/` and `crypto/*`. `builder/`, `schema/`, and `did/` depend on the core layer. `lifecycle/`, `verifier/`, and `witness/` sit on top of everything below them. This layering is enforced structurally — there are no back-edges, and adding one would break the separation that makes the SDK auditable.

## 4. The seven things every consumer must know

Before reading the rest of this document, internalize these seven invariants. Most of the SDK's design decisions follow mechanically from them.

1. **An entry is a signed, immutable byte sequence with two parts.** The Control Header carries protocol-level metadata the builder reads. The Domain Payload carries anything else and is opaque to the builder. The wall between them is absolute.

2. **Every entry is identified by its canonical SHA-256 hash.** Two implementations serializing the same logical entry must produce byte-identical bytes and therefore the same hash. The hash covers the preamble, header body, and payload — everything from byte 0 to the last payload byte.

3. **Every SMT leaf has two lanes.** `Origin_Tip` tracks content state (the current version of the entity). `Authority_Tip` tracks enforcement state (the current constraints on the entity). They are orthogonal; each path routes to one or the other.

4. **There are five state-affecting operations.** Path A (same signer), Path B (delegated), Path C (scope authority), commentary (zero SMT impact), new root entity (create leaf). A sixth, Path D, is the bit bucket — entries that failed to qualify under A/B/C end up here and have no SMT effect.

5. **Every consequential state transition follows publish → condition → activate.** An entry appears, conditions (delay, cosignatures, contest window) are met or not, and an activation entry finalizes the transition. The sole exception is Tier 2 key rotation, which uses pre-authorization via pre-commitments.

6. **The builder is local-only and mechanical.** It reads Control Headers, it fetches from its own log, it produces deterministic SMT mutations. It never reads Domain Payloads, never fetches from foreign logs, never evaluates domain semantics. Anything that requires those belongs in the verifier or in domain code.

7. **Writers prove, builders verify.** Authority proof is carried in the Control Header (delegation pointers, approval pointers, prior authority). The builder verifies what the writer supplied in O(N) where N is the size of the proof. No log scanning, no graph traversal, no unbounded work.

With those in mind, the rest of the SDK is a specific way of making them efficient and correct.

---

# Part II — Core Protocol Primitives

## 5. The entry envelope (`core/envelope`)

The envelope package defines the wire format for every entry. An entry is a bifurcated byte sequence: a 6-byte preamble, a variable-length header body, and a length-prefixed Domain Payload. Everything the protocol commits to — including entry identity, cross-entry references, cryptographic signatures, and the canonical hash — is derived from these bytes.

### 5.1 The wire format

Every serialized entry begins with:

```
Bytes 0–1:              uint16   Protocol_Version
Bytes 2–5:              uint32   Header_Body_Length (HBL)
Bytes 6 .. (6+HBL-1):   Header body fields (declaration order)
Bytes (6+HBL) .. :       uint32   Domain_Payload_Length
                         Domain Payload bytes
```

The first six bytes are fixed across all past and future protocol versions. No protocol upgrade can relocate, resize, redefine, or insert fields before them. This is what makes the format forward-compatible: a v5 parser reading a hypothetical v6 entry reads the preamble, parses the fields it knows about from the header body, skips any trailing bytes up to `6 + HBL`, and reads the payload. It does not need to understand any field introduced in v6 to extract the payload.

The current version is 5. A version policy state machine in `core/envelope/version_policy.go` governs which versions readers accept and which writers may emit. There are four states: `VersionActive` (read and write), `VersionDeprecated` (read-only, block writes), `VersionFrozen` (archival read-only, block writes), and `VersionRevoked` (cryptographically broken, block everything). At any time, exactly one version is `VersionActive`. Deserializing a v5 entry always works; emitting a new v5 entry works only while v5 is active.

### 5.2 The Control Header

The Control Header is the protocol-level metadata a builder reads. Its fields are defined in `envelope.ControlHeader` and the full list is in the source; the ones you'll encounter most often:

- `ProtocolVersion` — populated from the preamble.
- `SignerDID` — the DID whose signing key produced the signature over this entry.
- `TargetRoot` — the root entity this entry acts on. Nil for new root entities and commentary.
- `TargetIntermediate` — an optional intermediate entity whose `Origin_Tip` or `Authority_Tip` should also advance. This is the path-compression mechanism: one entry can update two leaves.
- `AuthorityPath` — the discriminator for Path A / B / C. Nil for commentary.
- `DelegateDID` — names the delegate on delegation entries.
- `DelegationPointers` — for Path B, the chain of delegation entries that connects signer to target. Capped at 3 hops.
- `ScopePointer` — for Path C, the scope entity whose `AuthoritySet` governs this entry.
- `AuthoritySet` — on scope-creation and scope-amendment entries, the complete updated set of authority DIDs.
- `PriorAuthority` — for Path C, the `Authority_Tip` the writer observed when constructing this entry (used for OCC).
- `ApprovalPointers` — cosignature entries approving a proposal, for scope amendments.
- `EvidencePointers` — supporting entries (cosignatures, attestations, witness confirmations) that establish activation. Capped at 32 except on authority snapshots.
- `SchemaRef` — pins the governing schema. Readers follow this to resolve activation delay, cosignature threshold, and other schema-declared parameters.
- `CosignatureOf` — on cosignature commentary entries, the entry being cosigned.
- `AuthoritySkip` — a verifier hint for fast authority-chain traversal.
- `EventTime` — the domain-asserted timestamp (distinct from `Log_Time`, which is operator-assigned metadata stored alongside the entry but outside the canonical hash).
- `AdmissionProof` — Mode B proof-of-work payload for permissionless admission.

Domain identity does not appear here. There is no "type", no "schema name", no "credential category" in the Control Header. Everything domain-specific lives in the Domain Payload.

### 5.3 Canonical serialization

Serialization is deterministic. Two implementations serializing the same logical `ControlHeader` and payload must produce byte-identical output. The rules:

- `uint16`, `uint32`, `uint64` in big-endian.
- Strings (including DIDs): `uint16` length prefix + UTF-8 bytes, ASCII-only for DIDs.
- Optional fields: 1-byte presence (0 or 1), then the value if present.
- Arrays: `uint16` count + concatenated elements.
- `AdmissionProof`: a length-prefixed sub-region, which isolates it from adjacent fields. This is the "SDK-3 isolation" guarantee — corruption of the admission proof can't bleed into `AuthoritySkip`.
- No padding, no alignment, no compression.

The canonical hash of an entry is `SHA-256` over the complete canonical serialization including the preamble. This hash is the entry's identity everywhere: Merkle leaves, Hashcash stamp binding, `CosignatureOf` references, `EvidencePointers` resolution, cross-log anchor references.

### 5.4 The three entry points

```go
func NewEntry(header ControlHeader, payload []byte) (*Entry, error)
func Serialize(e *Entry) []byte
func Deserialize(canonical []byte) (*Entry, error)
```

`NewEntry` is the only way to get an entry at the currently-active protocol version. It validates the header, overwrites `ProtocolVersion` to the active version, enforces size caps, and returns an entry that is guaranteed to serialize successfully.

`Serialize` is total — it never returns an error. If you constructed the entry via `NewEntry`, it will always produce valid bytes. Callers who hand-construct entries take responsibility for the result.

`Deserialize` enforces the read-version policy, parses the preamble, decodes fields, and tolerates unknown trailing bytes in the header body (forward compatibility for future additive fields).

### 5.5 Length limits and why

- `MaxCanonicalBytes = 1 MiB` — total serialized entry size. Enforced at `NewEntry` and `Deserialize`.
- `MaxDelegationPointers = 3` — delegation chain depth. Bounds Path B verification to O(3).
- `MaxEvidencePointers = 32` — cap on routine evidence arrays. Authority snapshot entries are exempt; they must reference every currently active enforcement entry and a partial snapshot would silently hide constraints.
- `MaxAdmissionProofBody = 4096` — caps the length-prefixed admission proof region.

These are bounded-computation guarantees. A malicious writer cannot submit an entry that takes unbounded time to validate.

## 6. The sparse Merkle tree (`core/smt`)

The SMT is where the protocol's state lives. Every root entity (credential, scope, schema, delegation, DID profile) occupies exactly one leaf. Every state-affecting entry updates one or two leaves. The tree's root hash, published periodically on the log and cosigned by state-map witnesses, is the commitment to current state.

### 6.1 Leaf keys and the two lanes

```go
func DeriveKey(pos types.LogPosition) [32]byte
```

The key for every leaf is `SHA-256(log_position)`, where `log_position` is the `(LogDID, Sequence)` pair of the root entity's creation entry. This rule is universal — there are no exceptions, no alternate derivations, no type-specific schemes.

Each leaf has exactly two fields that state-affecting entries mutate:

```go
type SMTLeaf struct {
    Key          [32]byte
    OriginTip    types.LogPosition  // current content state
    AuthorityTip types.LogPosition  // current enforcement state
}
```

When a root entity is created, the builder initializes its leaf with `OriginTip = AuthorityTip = log_position of the creation entry` — the leaf points at itself. Subsequent entries advance one or the other tip:

- Path A and Path B entries advance `OriginTip`. These are amendments, successions, revocations — changes to the entity's content.
- Path C enforcement entries advance `AuthorityTip`. These are sealing orders, suspensions, scope-level constraints.
- Path C scope-amendment entries (where `ScopePointer == TargetRoot` and `AuthoritySet` is present) advance `OriginTip`. A scope membership change is content evolution, not enforcement.

Path compression: when an entry sets `TargetIntermediate`, the builder updates that leaf's tip as well. An override entry, for example, sets `TargetRoot = entity` and `TargetIntermediate = contest entry`; both `AuthorityTip` fields advance in the same operation, making the override visible in O(1) from either direction.

### 6.2 The leaf store interfaces

The SMT package defines two interfaces that separate read-only from read-write access:

```go
type LeafReader interface {
    Get(key [32]byte) (*types.SMTLeaf, error)
}

type LeafStore interface {
    Get(key [32]byte) (*types.SMTLeaf, error)
    Set(key [32]byte, leaf types.SMTLeaf) error
    SetBatch(leaves []types.SMTLeaf) error
    Delete(key [32]byte) error
    Count() (int, error)
}
```

Verifiers take a `LeafReader` — they cannot mutate state. Builders take a `LeafStore`. Any `LeafStore` satisfies `LeafReader` through Go structural typing; no conversion is needed.

`SetBatch` has a strict atomicity contract: if it returns `nil`, every leaf in the slice was written; if it returns an error, no leaf was written. Implementations that can't guarantee this (best-effort file writes, non-transactional network stores) must not satisfy the interface. In-memory, Postgres, and RocksDB-backed stores all meet this naturally.

### 6.3 The overlay pattern

`OverlayLeafStore` wraps a backing `LeafStore` and buffers writes in memory:

```go
func NewOverlayLeafStore(backing LeafStore) *OverlayLeafStore
```

The overlay is the SDK's answer to a real problem. `builder.ProcessBatch` calls `SetLeaf` repeatedly as it processes entries. If the backing store is Postgres, each `SetLeaf` commits an INSERT that's durable independent of whether `ProcessBatch` finishes. If `ProcessBatch` processes 900 entries and fails on entry 901, the first 900 mutations are permanently written but the corresponding delta-buffer and queue updates (which the operator applies atomically after `ProcessBatch` returns) are never applied. The SMT state diverges from the metadata state.

The overlay solves this. The caller wraps the real store in an overlay, passes the overlay-backed tree to `ProcessBatch`, and — on success — iterates `result.Mutations` inside a single transaction to apply everything atomically to the real store. On failure, discarding the overlay costs nothing; no cleanup needed.

The contract: writes are buffered, not persisted. Reads fall through to the backing store only if the overlay has nothing for the key. The backing store is never modified by any operation on the overlay itself.

### 6.4 Mutation tracking

A tree can be put into tracking mode:

```go
func (t *Tree) StartTracking()
func (t *Tree) StopTracking() []types.LeafMutation
```

Between these calls, every `SetLeaf` and `SetLeaves` call records a `LeafMutation` with the key, old tips, and new tips. `StopTracking` returns the ordered list and disables tracking.

This is what makes fraud proofs possible. The state-map operator publishes `SMTDerivationCommitment` entries that include the mutation list for each batch. Any party can replay the batch against a tree seeded with the prior state, compare its own mutations to the committed ones, and produce O(1) evidence of any divergence. Section 24 covers this in detail.

### 6.5 Proofs

The SMT supports both membership and non-membership proofs, plus batch multiproofs that deduplicate shared path segments:

```go
func (t *Tree) GenerateMembershipProof(key [32]byte) (*types.SMTProof, error)
func (t *Tree) GenerateNonMembershipProof(key [32]byte) (*types.SMTProof, error)
func (t *Tree) GenerateBatchProof(keys [][32]byte) (*types.BatchProof, error)
```

Verification is via `smt.VerifyMembershipProof`, `smt.VerifyNonMembershipProof`, and `smt.VerifyBatchProof`. Each takes a proof and a trusted root (typically a cosigned SMT root obtained from a witness).

Single proofs are roughly 1.1 KB (~35 non-default hashes × 32 bytes). Batch multiproofs scale sublinearly with the number of entries — a 5-entry credential chain verification is about 3.8 KB, compared to 11 KB of individual proofs.

## 7. Shared types (`types/`)

The `types/` package is intentionally minimal. It contains only data types with no logic, no external dependencies beyond the standard library, and no interfaces. Its purpose is to define a shared vocabulary that every other package can import without creating dependency cycles.

The types you'll see everywhere:

- `LogPosition { LogDID string, Sequence uint64 }` — the protocol's universal pointer. Every reference to an entry, anywhere in the system, is a `LogPosition`.
- `SMTLeaf { Key, OriginTip, AuthorityTip }` — the two-lane leaf structure described in section 6.
- `LeafMutation` — the change record used for derivation commitments.
- `EntryWithMetadata { CanonicalBytes, Position, LogTime, SignatureAlgoID, SignatureBytes }` — what the operator returns when you fetch an entry. `LogTime` is the operator-assigned admission timestamp, stored alongside the entry but outside the canonical hash.
- `TreeHead`, `CosignedTreeHead`, `WitnessSignature`, `WitnessPublicKey`, `WitnessRotation` — the witness infrastructure vocabulary (see Part VIII).
- `MerkleProof`, `SMTProof`, `BatchProof`, `CrossLogProof` — the four proof formats.
- `SchemaParameters` — the struct that `schema.SchemaParameterExtractor` populates from a schema entry's Domain Payload. Contains `ActivationDelay`, `CosignatureThreshold`, `MaturationEpoch`, `CredentialValidityPeriod`, `OverrideThreshold`, `OverrideRequiresIndependentWitness`, `MigrationPolicy`, `ArtifactEncryption`, `GrantAuthorizationMode`, and a few more.
- `OverrideThresholdRule` — a typed enum (`ThresholdTwoThirdsMajority`, `ThresholdSimpleMajority`, `ThresholdUnanimity`) with a `RequiredApprovals(N int) int` method. Replaces the older hardcoded ⌈2N/3⌉ with a schema-driven choice.
- `AdmissionProof` — the API form of Mode B stamps (distinct from the wire-format `envelope.AdmissionProofBody`; a small adapter in `crypto/admission/adapter.go` translates between them).

The rule for this package: if it needs logic, it goes somewhere else. The types are the contract between layers. Logic against those types belongs in the layer that owns it.

## 8. Content-addressed storage (`storage/`)

Artifacts — credential attachments, encrypted payloads, mapping blobs, escrow packages — live off-log in content-addressed blob storage. The log carries CIDs (content identifiers) that reference them. The `storage/` package defines the CID format, the storage interface, and a reference in-memory implementation.

### 8.1 CIDs

```go
type CID struct {
    Algorithm HashAlgorithm
    Digest    []byte
}

func Compute(data []byte) CID              // SHA-256 by default
func ComputeWith(data []byte, algo HashAlgorithm) CID
func (c CID) Verify(data []byte) bool
func (c CID) Equal(other CID) bool
func (c CID) String() string                // "sha256:abc123..."
func ParseCID(s string) (CID, error)
```

The default algorithm is SHA-256 (tag `0x12`), but the format supports additional algorithms through `RegisterAlgorithm`. `Verify` is constant-time. The string form is `name:hex` (e.g., `sha256:abc...`), and `Bytes()` produces a compact wire encoding as `[algo_tag][digest]`.

### 8.2 The ContentStore interface

```go
type ContentStore interface {
    Push(cid CID, data []byte) error
    Fetch(cid CID) ([]byte, error)
    Pin(cid CID) error
    Exists(cid CID) (bool, error)
    Delete(cid CID) error
}
```

The critical property: **the SDK computes the CID, then calls the backend.** The backend receives `(cid, data)` and stores them. It never hashes. This means two backends storing the same bytes produce the same CID — addressing is controlled by the SDK, not by storage-specific conventions.

`ErrContentNotFound` from `Fetch` is a normal condition, not an error. Cryptographic erasure destroys a key; the ciphertext may or may not remain in the store. Code that decrypts artifacts expects either success or `ErrContentNotFound` — it doesn't treat missing content as an anomaly.

`ErrNotSupported` is returned by backends that can't implement a specific operation. IPFS returns it from `Delete` (IPFS has best-effort garbage collection, not guaranteed deletion). GCS and S3 backends implement `Delete` fully.

### 8.3 The RetrievalProvider interface

`ContentStore` is the write-side. The read-side — "how do I give someone else a way to fetch these bytes?" — is `RetrievalProvider`:

```go
type RetrievalProvider interface {
    Resolve(artifactCID CID, expiry time.Duration) (*RetrievalCredential, error)
}

type RetrievalCredential struct {
    Method string     // MethodSignedURL, MethodIPFS, MethodDirect
    URL    string
    Expiry *time.Time // nil for IPFS and direct
}
```

The artifact store implements this per backend: GCS produces a V4 signed URL, S3 produces a presigned URL, IPFS produces a gateway URL with no expiry. The operator calls `Resolve` when a caller asks for access to an artifact and passes the resulting credential back through the exchange. The operator never generates signed URLs itself — storage credentials stay at the artifact store.

The `Method` field is a capability, not a provider. Backends pick from `MethodSignedURL`, `MethodIPFS`, or `MethodDirect`. New provider integrations don't add new methods unless the retrieval mechanic is genuinely novel. A new IPFS gateway and a new S3-compatible backend both use existing methods.

### 8.4 Reference and HTTP implementations

The SDK ships three implementations of `ContentStore`:

- `InMemoryContentStore` — for tests and local development. Fully supports `Delete`. Thread-safe.
- `HTTPContentStore` — calls `ortholog-artifact-store`'s REST API. Maps `Push` to `POST /v1/artifacts`, `Fetch` to `GET`, etc.
- (Backend-specific stores like `GCSContentStore` and `IPFSContentStore` live in the artifact-store repo, not here. The SDK doesn't import cloud SDKs.)

And two implementations of `RetrievalProvider`:

- `InMemoryRetrievalProvider` — returns `MethodDirect` with URL equal to the CID string. Testing only.
- `HTTPRetrievalProvider` — calls the artifact store's `GET /v1/artifacts/{cid}/resolve?expiry=N` endpoint.

When you build a domain application, you inject one of these (or write your own) at wiring time. The SDK's lifecycle and artifact-access code accepts the interface — it doesn't care which implementation you passed.

---

# Part III — The Builder

The builder is the component that turns a stream of entries into SMT state changes. It is the most mechanically important part of the SDK: everything above it (verifier, lifecycle, witness infrastructure) assumes the builder produces identical output on identical input across every correct implementation, forever. This section is organized by what you need to know.

Most readers of this guide need sections 9 and 10. Section 11 is operator-implementer territory; domain builders and verifier authors can skip it until a specific problem sends them back.

## 9. Builder pipeline and path routing

### 9.1 The one function that matters

```go
func ProcessBatch(
    tree *smt.Tree,
    entries []*envelope.Entry,
    positions []types.LogPosition,
    fetcher EntryFetcher,
    schemaRes SchemaResolver,
    localLogDID string,
    deltaBuffer *DeltaWindowBuffer,
) (*BatchResult, error)
```

`ProcessBatch` is the one function a domain application calls to advance SMT state. You give it a tree, a slice of entries with their log positions, a fetcher that can resolve other log positions to entries, a schema resolver (optional — nil means strict OCC everywhere), the DID of the log that owns this batch, and a delta-window buffer carried over from the previous batch.

It returns a `BatchResult`:

```go
type BatchResult struct {
    NewRoot          [32]byte
    Mutations        []types.LeafMutation
    PathACounts      int
    PathBCounts      int
    PathCCounts      int
    PathDCounts      int
    CommentaryCounts int
    NewLeafCounts    int
    RejectedCounts   int
    UpdatedBuffer    *DeltaWindowBuffer
}
```

The mutations list is what you persist (along with `NewRoot`) atomically to your backing store. The path counts are observability and retry signals. The updated buffer carries delta-window state forward for the next batch.

Two things to know up front:

**Partial-batch behavior is not transactional across entries.** If entry 5 succeeds and entry 6 hits a tree-mutation failure in its apply phase, entry 5's mutations stay in the tree. The within-entry compute-then-apply pattern (section 9.4) prevents partial mutations for a single entry, but does not roll back prior entries. Callers needing all-or-nothing semantics process entries one at a time, or wrap `ProcessBatch` in an operator-level transaction using the overlay pattern from section 6.3.

**A non-nil error from `ProcessBatch` is fatal for the batch.** Per-entry failures surface as `PathResultPathD` or `PathResultRejected` in the counts — they're not errors. An error return means something broke at the batch level: length mismatch between entries and positions, tree corruption, or root computation failure. Treat the batch as untrustworthy and don't publish the root.

### 9.2 Path classification

Every entry lands in exactly one of seven buckets. The sum of all bucket counts equals `len(entries)`.

```go
const (
    PathResultCommentary PathResult = iota  // no SMT impact
    PathResultNewLeaf                        // creates a new leaf
    PathResultPathA                          // same-signer amendment
    PathResultPathB                          // delegated authority
    PathResultPathC                          // scope authority
    PathResultPathD                          // failed to qualify
    PathResultRejected                       // violated structural invariant
)
```

The distinction between PathD and Rejected matters for operational reasons. PathD means "this entry didn't qualify for any path, SMT not modified, entry still on the log" — a common and normal outcome (foreign log reference, missing target, stale OCC). Rejected means "this entry violated a structural invariant and should never have been admitted" — an operational anomaly to flag in monitoring.

The routing logic:

- `TargetRoot == nil`:
  - `AuthorityPath == nil` → **Commentary** (no leaf created or modified)
  - `AuthorityPath != nil` → **NewLeaf** (root entity; creates leaf with `Origin_Tip = Authority_Tip = self`)
- `TargetRoot != nil`:
  - `TargetRoot.LogDID != localLogDID` → **PathD** (foreign target; builder is local-only, Decision 47)
  - Target entry not fetchable, leaf missing, evidence cap exceeded on non-snapshot → **PathD** or **Rejected**
  - `AuthorityPath == AuthoritySameSigner` and signer matches → **PathA**
  - `AuthorityPath == AuthorityDelegation` and chain connects → **PathB**
  - `AuthorityPath == AuthorityScopeAuthority` and signer in scope's AuthoritySet with valid OCC → **PathC**
  - Otherwise → **PathD**

### 9.3 What each path does to the leaf

**Path A (same signer).** `E_new.SignerDID == targetEntry.SignerDID`. Advances `OriginTip` of the target leaf. If `TargetIntermediate` is set, also advances that leaf's `OriginTip`. Used for amendments, successions, revocations, key rotations, artifact re-encryptions.

**Path B (delegation).** `E_new.Signer` connects to `targetEntry.Signer` through a chain of up to 3 delegation entries listed in `DelegationPointers`. Each delegation must be live (its leaf's `OriginTip == its own position` — not revoked, not amended). Advances `OriginTip` of the target leaf. Used when a delegate issues amendments on behalf of the root entity.

**Path C (scope authority).** `E_new.Signer` is a member of the scope's current `AuthoritySet`. The entry's `Approval_Pointers` reference cosignature entries from other scope members (used for scope amendments). `Prior_Authority` must match the target leaf's current `Authority_Tip` (strict OCC) or fall within the Δ-window (commutative OCC, see section 10.1). Two sub-cases:

- **Scope amendment** (`ScopePointer == TargetRoot` and `AuthoritySet` is present) — advances `OriginTip`. Changing membership is content evolution.
- **Enforcement** (everything else) — advances `Authority_Tip`. Internal constraints on the entity.

Both sub-cases also update `TargetIntermediate` if set.

**Commentary.** No TargetRoot, no AuthorityPath. Zero SMT impact. Used for cosignature entries (with `CosignatureOf`), witness attestations, recovery requests, anchor entries, mirror entries. The log records them; the SMT doesn't reflect them. Verifiers and domain code discover commentary through query indexes.

**NewLeaf.** No TargetRoot, AuthorityPath set. Creates a new leaf with both tips pointing at the entry's own log position. This is how every root entity — credential, scope, schema, delegation, DID profile — enters the SMT.

### 9.4 The compute-then-apply pipeline

Each path processor inside `builder/algorithm.go` runs in two phases:

1. **Compute phase.** Pure. Validates monotonicity, locality, and existence invariants; builds a `[]leafUpdate` list. No SMT writes, no delta-buffer records. If any validation fails, zero mutations have happened and the entry is classified and rejected cleanly.

2. **Apply phase.** `applyLeafUpdates` writes each staged update to the SMT in sequence and records delta-buffer entries only after successful commits.

This structure eliminates a whole bug class. You can't end up with an intermediate leaf advanced but the main leaf left behind because the main leaf's validation rejected. All validation completes before any state is mutated.

The invariants the compute phase enforces:

- **Monotonicity.** Tips only advance. If a new tip has the same `LogDID` as the old tip, its `Sequence` must strictly exceed the old one. Cross-log transitions bypass the sequence check (you can't compare sequences across logs).
- **Locality.** Target and intermediate entries must be on the local log. A foreign reference falls through to PathD.
- **Existence.** Intermediate leaves must exist. A missing intermediate is not a silent no-op — it's an error that routes the entry to PathD.

### 9.5 The EntryFetcher contract

```go
type EntryFetcher interface {
    Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error)
}
```

Implemented by the operator's query layer in production, and by `MockFetcher` in tests. Returns `(nil, nil)` when the position has no entry — this is a normal outcome during chain walks, not an error. Returns a non-nil error only for transport or storage failures the caller should propagate.

The builder calls `Fetch` when it needs to resolve a `LogPosition` referenced in a Control Header: `TargetRoot`, delegation pointers, approval pointers, scope pointers. It never fetches from foreign logs (locality). It never fetches Domain Payloads from CAS (bounded work).

## 10. Concurrency and optimization invariants

### 10.1 Optimistic concurrency control

Path C entries carry `Prior_Authority` — the `Authority_Tip` the writer observed when constructing the entry. The builder verifies this matches current state before accepting the entry.

The default mode is **strict OCC**: `Prior_Authority` must exactly equal the target leaf's current `Authority_Tip`. Mismatch means someone else's Path C entry landed first and the writer's entry was built against stale state. The builder rejects it; the writer retries with the new tip. Exponential backoff in `builder.ProcessWithRetry` handles the retry loop.

Schemas can opt into **commutative OCC** for operations that are semantically order-independent — independent observations, parallel attestations, accumulating signatures on a multi-party agreement. A schema declares commutativity through its `Commutative_Operations` field; the builder reads this (via `SchemaResolver`) on entries that reference the schema. When commutative, `Prior_Authority` must reference a state within the last N `Authority_Tip` values for the target leaf (N defaults to 10, schema-configurable). Concurrent valid operations within the window are all accepted.

The Δ-window is maintained by the `DeltaWindowBuffer`:

```go
type DeltaWindowBuffer struct { /* ... */ }
func NewDeltaWindowBuffer(windowSize int) *DeltaWindowBuffer
```

The buffer is **builder working memory**, not part of the SMT leaf, the log, or any proof format. It lives between `ProcessBatch` calls; the operator persists it alongside the tree root. A missing or cold-start buffer is treated as "no history" — the first batch after cold start functions as strict OCC for all entries, which is conservative and safe.

Critical constraint on commutative declarations: a schema declaring operations commutative is asserting that every Path C entry under that schema is semantically order-independent. The builder cannot distinguish operation types within a schema — it reads Control Header fields only. If a scope needs both commutative and non-commutative operations, it publishes two schemas. Schema certification includes elevated audit of commutativity claims, because a schema that incorrectly declares non-commutative operations as commutative produces silent semantic corruption that the SMT cannot detect.

### 10.2 Retry wrapping

Most operators don't call `ProcessBatch` directly — they call `ProcessWithRetry`:

```go
func ProcessWithRetry(p ProcessWithRetryParams) (*RetryResult, error)
```

The wrapper detects `RejectedCounts > 0` on the result, waits with exponential backoff, and retries. Between attempts, concurrent batches on other goroutines may have advanced the tree state and the delta buffer — the retry may succeed because the writer's `Prior_Authority` is no longer stale (it now falls within an updated Δ-window) or because whatever intermediate state was missing has arrived.

`DefaultRetryConfig()` gives you 5 attempts, 50ms base delay, 5s max. `BatchRetryConfig()` gives you 10 attempts, 200ms base, 10s max — intended for coordinated enforcement where more than 10 simultaneous authorities write against the same entity and collisions are expected.

The wrapper does not re-fetch entries or re-resolve schemas between attempts. It re-runs `ProcessBatch` with the same inputs against a potentially advanced tree and buffer. That's all it needs.

### 10.3 Evidence pointer cap and the snapshot exemption

`MaxEvidencePointers = 32` applies to most entries. The exception: authority snapshot entries, which must reference every currently active enforcement entry and therefore can't be capped. A partial snapshot would silently hide active constraints from verifiers that trust the snapshot shortcut.

The builder detects snapshots by shape: `AuthorityPath == AuthorityScopeAuthority` AND `TargetRoot != nil` AND `PriorAuthority != nil`. Exactly those entries get the exemption. The rule is in `isAuthoritySnapshot`; the envelope's `NewEntry` validator applies the same rule so malformed snapshots never reach the builder.

### 10.4 Authority snapshots and skip pointers

The `Authority_Tip` chain is walked backward through `Prior_Authority`. For a long-lived entity with many enforcement actions, this chain can grow large. Two mechanisms compress it:

**Authority snapshot entries.** A scope authority publishes a snapshot via Path C whose `Evidence_Pointers` reference every currently active enforcement. The builder accepts this as the new `Authority_Tip`. A verifier walking the chain encounters the snapshot, reads the evidence pointers, and has the full active constraint set without walking historical enforcement. Chain complexity drops from O(total historical enforcement) to O(currently active constraints), typically 0–3.

**Authority skip pointers.** `Authority_Skip` is an optional writer-provided hint pointing to an earlier state in the chain. The builder records it but doesn't use it. Verifiers consult it during traversal: follow the skip, verify consistency (the skip target must be reachable via `Prior_Authority` from the current entry), and either accept it for O(log A) traversal or ignore it and fall back to linear walk. An invalid skip pointer wastes O(1) verifier time — no security impact, no incorrect result.

Snapshots compact *at a point*; skip pointers accelerate traversal *between* snapshots. Both are additive optimizations. A chain with neither is O(A); with skip pointers it's O(log A); with a snapshot it's O(active constraints).

### 10.5 The locality rule (Decision 47)

The builder fetches entries from the local log exclusively. Control Header fields referencing log positions on foreign logs are unresolvable by the builder — the entry falls through to PathD.

Cross-log authority requires local representation. If scope A on log X wants to delegate authority to an actor on log Y, the delegation must be mirrored by a local delegation entry on log Y. Cross-log integrity of the justifying entry is the verifier's responsibility; at read time, verifiers validate the foreign reference through a `CrossLogProof` (section 24). The builder never reads a foreign log.

This rule exists because the builder is the synchronous, bounded-computation path. Allowing it to follow foreign references would introduce liveness dependencies on other logs, open up unbounded work, and make batch processing's timing guarantees impossible.

## 11. Builder internals reference

Skip this section unless you're implementing an operator, porting the SDK to another language, or debugging a specific builder behavior.

### 11.1 Read-only entry classification

The builder also exposes a read-only classifier that determines what path an entry *would* take without mutating the tree:

```go
type Classification struct {
    Path    PathResult
    Reason  string
    Details ClassificationDetails
}

func ClassifyEntry(p ClassifyParams) (*Classification, error)
func ClassifyBatch(entries []*envelope.Entry, positions []types.LogPosition,
                   leafReader smt.LeafReader, fetcher EntryFetcher,
                   logDID string) ([]Classification, error)
```

This is useful for pre-admission: an operator can classify an entry before accepting it into the log and reject obvious PathD candidates at the API layer, saving log space. It's also useful for debugging — the `Reason` field explains *why* an entry got the path it did ("delegation chain does not connect to target signer", "Prior_Authority != Authority_Tip — commutative check not available in read-only mode"). The `ProcessBatch` path collapses these reasons into PathD counts; use `ClassifyBatch` when you need the explanations.

Classification does one thing the writable path doesn't fully do: it returns per-entry failure reasons. `ProcessBatch` collapses all non-fatal failures into PathD for counting, so downstream code that needs to know "why did entry 7 not advance state" uses `ClassifyEntry` before submission.

### 11.2 Path B chain assembly

Building a Path B entry requires assembling a valid delegation chain. The SDK provides an assembler:

```go
type AssemblePathBParams struct {
    DelegateDID        string
    TargetRoot         types.LogPosition
    LeafReader         smt.LeafReader
    Fetcher            EntryFetcher
    MaxDepth           int  // 0 = default 3
    CandidatePositions []types.LogPosition
}

func AssemblePathB(params AssemblePathBParams) (*PathBAssembly, error)
```

The caller supplies the positions of delegation entries they know about. The assembler validates each one, connects them into a chain from `DelegateDID` back to the root entity's signer, and returns the ordered `DelegationPointers` ready for `BuildPathBEntry`. Errors identify specific failures: `ErrChainTooDeep`, `ErrChainDisconnected`, `ErrChainCycle`, `ErrDelegationNotLive`.

A companion function validates liveness after assembly:

```go
func ValidateChainLiveness(params ValidateChainParams) (*ChainLivenessResult, error)
```

Use this right before submission to catch delegation revocations that happened between assembly and submission.

### 11.3 The 18 typed entry builders

Every domain application uses the typed builders in `builder/entry_builders.go` rather than populating Control Headers by hand. The builders validate domain-specific preconditions, populate fields correctly for each path, and delegate to `envelope.NewEntry` for normalization.

Origin-lane builders (5):
- `BuildRootEntity` — new root entity (credential, profile, anything that creates a new leaf)
- `BuildAmendment` — Path A amendment
- `BuildDelegation` — new delegation entry
- `BuildSuccession` — bridge old to new signer on the same entity
- `BuildRevocation` — Path A revocation

Authority-lane builders (3):
- `BuildScopeCreation` — new scope entity with Authority_Set
- `BuildScopeAmendment` — Path C scope membership change
- `BuildScopeRemoval` — Path C N-1 removal execution

Enforcement (1):
- `BuildEnforcement` — generic Path C enforcement (sealing orders, suspensions, scrub determinations)

Commentary (4):
- `BuildCommentary` — generic zero-SMT-impact entry
- `BuildCosignature` — cosignature referencing another entry
- `BuildRecoveryRequest` — initiates escrow recovery
- `BuildAnchorEntry` — cross-log tree-head anchor

Key management (2):
- `BuildKeyRotation` — Path A rotation against DID profile
- `BuildKeyPrecommit` — pre-commitment for Tier 2 rotation

Schema (1): `BuildSchemaEntry`
Delegation use (1): `BuildPathBEntry` — consumes the output of `AssemblePathB`
Cross-log (1): `BuildMirrorEntry` — commentary entry mirroring a foreign log entry

Each builder takes a typed parameter struct and returns `(*envelope.Entry, error)`. The errors are specific: `ErrEmptySignerDID`, `ErrMissingTargetRoot`, `ErrMissingDelegateDID`, `ErrMissingScopePointer`, `ErrEmptyAuthoritySet`, etc. You never see a generic "bad entry" error — the builder tells you which field is wrong.

### 11.4 SchemaResolver and why it's optional

```go
type SchemaResolver interface {
    Resolve(ref types.LogPosition, fetcher EntryFetcher) (*SchemaResolution, error)
}

type SchemaResolution struct {
    IsCommutative   bool
    DeltaWindowSize int
}
```

If you pass `nil` to `ProcessBatch`, the builder treats every schema as non-commutative (strict OCC). This is the safe default. A non-nil resolver is required only if any schema on the log declares commutative operations — the resolver reads the schema entry's Control Header's `CommutativeOperations` field and reports whether it's non-empty.

The SDK ships `schema.CachingResolver` (in the `schema/` package, not `builder/`) which satisfies the interface and caches resolutions by log position.


---

# Part IV — Cryptography

The SDK ships five cryptographic primitives, one per package. Each has a distinct threat model and distinct guarantees. This part covers what each does, what it protects against, and where its limits are.

## 12. Canonical hashing (`crypto/hash`)

The simplest package. Two functions:

```go
func CanonicalHash(entry *envelope.Entry) [32]byte
func HashBytes(data []byte) [32]byte
```

`CanonicalHash` is `SHA-256(envelope.Serialize(entry))`. It is the entry's cryptographic identity for everything that references entries: Merkle leaves, Hashcash stamp binding, `Cosignature_Of` verification, `Evidence_Pointers` resolution, cross-log anchor references, the deterministic lexicographic sort that commutative CRDT resolution uses.

The value of keeping this in its own package: every consumer that hashes an entry uses this function. There is one place to audit and one place to change if the hash algorithm ever needs to evolve (it doesn't, but the discipline matters).

`HashBytes` is trivially `SHA-256`, used by every other layer that needs a hash over arbitrary bytes without constructing a full `Entry`.

## 13. Signatures (`crypto/signatures`)

Two kinds of signatures in the protocol: **entry signatures** (one signer per entry, produced by whoever authored the entry) and **witness cosignatures** (K of N signers, produced by the witness infrastructure over cosigned tree heads).

### 13.1 Entry signatures

Entry signatures use ECDSA on secp256k1. The same curve is reused by ECIES in `crypto/escrow` and by Umbral PRE in `crypto/artifact`, so every signing key in the system is ultimately a secp256k1 key.

```go
func GenerateKey() (*ecdsa.PrivateKey, error)
func SignEntry(hash [32]byte, privkey *ecdsa.PrivateKey) ([]byte, error)
func VerifyEntry(hash [32]byte, sig []byte, pubkey *ecdsa.PublicKey) error
func PubKeyBytes(pub *ecdsa.PublicKey) []byte
func ParsePubKey(data []byte) (*ecdsa.PublicKey, error)
```

Three properties of the signer:

**Low-S normalization.** `SignEntry` normalizes to low-S form (`s ≤ N/2`). Raw ECDSA is malleable — given `(r, s)`, the pair `(r, -s mod N)` is also a valid signature. Low-S normalization eliminates this. Without it, an adversary who observes a valid entry signature could produce a second signature over the same hash, and any downstream code that uses the signature bytes as an identity key would treat them as distinct signatures.

**Rigorous 32-byte padding for R and S.** The output is always 64 bytes. `big.Int.Bytes()` strips leading zeros, which would produce 31-byte serializations about 1 in 256 times. The signer zero-pads explicitly so every signature is exactly 64 bytes, everywhere, always.

**Non-zero component check in Verify.** A signature with `r = 0` or `s = 0` is rejected before the curve math runs. This catches corruption and malformed signatures fast.

Signatures are wire-format-wrapped via `AppendSignature` / `StripSignature` in `envelope/signature_wire.go`. The wire format after the canonical entry is `[uint16 algo_id][uint32 sig_len][sig_bytes]`. Two algorithm IDs are defined: `SigAlgoECDSA = 0x0001` and `SigAlgoEd25519 = 0x0002`. The protocol does not mandate a specific algorithm — signers choose, and verifiers dispatch on the ID.

### 13.2 Witness cosignatures

A cosigned tree head carries K of N witness signatures. The scheme used is identified by a single-byte tag on the head:

- `SchemeECDSA = 0x01` — K independent ECDSA signatures, 64 bytes each.
- `SchemeBLS = 0x02` — K BLS signatures aggregated into a single 48-byte signature.

```go
func VerifyWitnessCosignatures(
    head types.CosignedTreeHead,
    witnessKeys []types.WitnessPublicKey,
    K int,
    blsVerifier BLSVerifier,
) (*WitnessVerifyResult, error)
```

The function dispatches on `head.SchemeTag`. ECDSA verification runs K independent ECDSA verifications locally. BLS verification delegates to an injected `BLSVerifier`:

```go
type BLSVerifier interface {
    VerifyAggregate(msg []byte, signatures []types.WitnessSignature,
                    pubkeys []types.WitnessPublicKey) ([]bool, error)
}
```

The SDK doesn't ship a BLS implementation directly — BLS12-381 requires heavy dependencies and precompile availability varies across deployment targets. Consumers who need BLS inject a verifier backed by whatever library is appropriate for their environment. Consumers running on ECDSA-only deployments pass nil and never touch BLS.

The scheme tag exists specifically to support transitions. When a witness set rotates from ECDSA to BLS, the rotation message is dual-signed (both schemes), and light clients update their expected scheme atomically with the rotation. Section 26 covers rotation in full.

### 13.3 The witness cosign message

```go
func WitnessCosignMessage(head types.TreeHead) [40]byte
```

This is the 40-byte structure witnesses sign over. The format: `[32-byte root hash][uint64 big-endian tree size]`. The SDK hashes it (SHA-256) before passing to ECDSA verification. Two implementations producing the same `TreeHead` must produce byte-identical cosign messages — any divergence here breaks the witness verification contract.

## 14. Artifact encryption (`crypto/artifact`)

Artifact encryption is **storage encryption** — protecting the bytes at rest. The primitive is AES-256-GCM. On top of that, schemas can opt into **access control** via Umbral Threshold Proxy Re-Encryption (Umbral PRE). These are layered, not alternatives: Umbral PRE wraps AES keys, it doesn't replace AES.

### 14.1 AES-256-GCM storage encryption

```go
type ArtifactKey struct {
    Key   [32]byte
    Nonce [12]byte
}

func EncryptArtifact(plaintext []byte) (ciphertext []byte, key ArtifactKey, err error)
func DecryptArtifact(ciphertext []byte, key ArtifactKey) ([]byte, error)
func ReEncryptArtifact(ciphertext []byte, oldKey ArtifactKey) ([]byte, ArtifactKey, error)
func ZeroKey(key *ArtifactKey)
```

One key per artifact. Per-artifact keys are generated fresh for every encryption — there's no master key that encrypts multiple artifacts. This is deliberate. Cryptographic erasure works by destroying the key; sharing keys across artifacts breaks erasure semantics.

`ReEncryptArtifact` decrypts with the old key, re-encrypts with a fresh key, and zeros the plaintext in a deferred block — so even if `EncryptArtifact` fails mid-re-encryption, the plaintext doesn't linger in memory.

`VerifyAndDecrypt` is the integrity-checked decryption path used by anything that consumes artifacts:

```go
func VerifyAndDecrypt(ciphertext []byte, key ArtifactKey,
                     artifactCID storage.CID, contentDigest storage.CID) ([]byte, error)
```

It checks ciphertext-CID match, decrypts, then checks plaintext-digest match. Failures return `IrrecoverableError`, which is a distinct type so callers can distinguish "decryption failed, no point retrying" from "transient storage error, try again later." There's a package-level `IsIrrecoverable(err)` helper for this check.

### 14.2 Umbral PRE — access control

Umbral PRE is the SDK's answer to "how do I grant Alice the ability to decrypt this artifact without giving her my master key and without the exchange ever seeing plaintext?"

The primitives are in `crypto/artifact/pre.go`:

```go
func PRE_Encrypt(pk []byte, plaintext []byte) (*Capsule, []byte, error)
func PRE_Decrypt(sk []byte, capsule *Capsule, ciphertext []byte) ([]byte, error)
func PRE_GenerateKFrags(skOwner, pkRecipient []byte, M, N int) ([]KFrag, error)
func PRE_ReEncrypt(kfrag KFrag, capsule *Capsule) (*CFrag, error)
func PRE_VerifyCFrag(cfrag *CFrag, capsule *Capsule, vkX, vkY *big.Int) error
func PRE_DecryptFrags(skRecipient []byte, cfrags []*CFrag, capsule *Capsule,
                     ciphertext []byte, pkOwner []byte) ([]byte, error)
```

The flow:

1. Owner encrypts artifact for their own public key: `PRE_Encrypt(pk_owner, plaintext)` returns a `Capsule` (public, storable in Domain Payload) and ciphertext.
2. To grant Alice access, owner generates M-of-N re-encryption key fragments for Alice's public key: `PRE_GenerateKFrags(sk_owner, pk_alice, M, N)`. Each kfrag is given to one re-encryption node.
3. Each node runs `PRE_ReEncrypt(kfrag, capsule)` to produce a CFrag carrying a DLEQ (discrete-log equality) proof that re-encryption was performed correctly. No node sees plaintext. Any monitoring service can verify the CFrag via `PRE_VerifyCFrag` using only public data.
4. Alice collects M CFrags and runs `PRE_DecryptFrags(sk_alice, cfrags, capsule, ciphertext, pk_owner)` to recover the plaintext.

The cryptographic core is ECIES on secp256k1: an ephemeral ECDH key exchange generates a DEM key that encrypts the payload; the capsule binds the ephemeral point to the owner's public key without leaking the shared secret. The `V` component of the capsule is `r * hashToPoint(pk_owner)`, not `r * pk_owner` — this is a security fix. Storing `r * pk_owner` would leak the DH shared secret.

### 14.3 The delegation key isolation defense

Scalar-multiplication PRE schemes on secp256k1 have a specific collusion vulnerability. The re-encryption key is `rk = sk_owner / d mod n` where `d = H(sk_recipient * pk_owner)`. If the recipient colludes with M re-encryption nodes, they can reconstruct `rk` via Lagrange interpolation. The recipient knows `d` (they can compute it). So they can extract `sk_owner = rk * d mod n`.

The SDK neutralizes this in `lifecycle/delegation_key.go`:

```go
func GenerateDelegationKey(ownerPubKey []byte) (pkDel []byte, wrappedSkDel []byte, err error)
func UnwrapDelegationKey(wrappedSkDel []byte, ownerSecretKey []byte) ([]byte, error)
```

Instead of using `sk_owner` directly, every artifact gets its own ephemeral delegation key pair `(sk_del, pk_del)`. At publish time, the SDK generates the delegation key, uses `pk_del` in the capsule, and ECIES-wraps `sk_del` for the owner's master public key. The wrapped `sk_del` lives in the artifact key store keyed by CID; `sk_owner` stays in the HSM.

At grant time, the owner's HSM or enclave unwraps `sk_del` and passes it — not `sk_owner` — to `PRE_GenerateKFrags`. If the recipient colludes with M proxies and extracts the key, they extract `sk_del` — a disposable key that only decrypts the single artifact the recipient already had permission to access. Zero lateral movement. The master identity key is mathematically isolated.

This is a structural defense, not a cryptographic one. You can't find it in the Umbral paper. It matters because the SDK is domain-agnostic and some deployments will hold keys across many artifacts for the same identity — without the delegation key pattern, a single successful collusion attack would compromise the entire identity.

## 15. Key escrow (`crypto/escrow`)

Key escrow is the protocol's recovery mechanism. When a holder's signing key is lost or an exchange fails, M-of-N escrow nodes cooperate to reconstruct the key material under the existing Authority_Set's supervision.

### 15.1 Shamir splitting in GF(256)

```go
func SplitGF256(secret []byte, M, N int) ([]Share, error)
func ReconstructGF256(shares []Share) ([]byte, error)
```

Threshold secret sharing over the Rijndael (AES) field. Each share is a byte string of the same length as the secret; any M shares reconstruct it. The implementation uses Horner's method to evaluate a polynomial and Lagrange interpolation at x=0 to reconstruct.

The constraint: `1 ≤ M ≤ N ≤ 255`. Share index 0 is reserved (it would reveal the secret), so indices run 1..N.

### 15.2 Field-tagged shares

Shamir has a subtle failure mode across field choices. If you split in GF(256) but try to reconstruct in Z_p (a different field used by some alternative implementations), the mathematics produces a valid-looking byte string that isn't the secret. AES-256-GCM decryption with the wrong key produces garbage or authentication failure, silently destroying the holder's recoverable material with no error signal.

The SDK defends against this with a one-byte field identifier tag on every share:

```go
type Share struct {
    FieldTag byte     // 0x01 = GF(256), 0x02 = Z_p
    Index    byte
    Value    []byte
}
```

`ReconstructGF256` checks every share's tag before computation and rejects mixed or unrecognized tags with an explicit error. `VerifyShare` validates a single share's structural integrity (tag, non-zero index, 32-byte value) during collection, so invalid shares are rejected as they arrive rather than poisoning reconstruction.

### 15.3 Wire format

```go
func SerializeShare(s Share) ([]byte, error)
func DeserializeShare(data []byte) (Share, error)
```

Fixed 34 bytes: `[1-byte tag][1-byte index][32-byte value]`. The 32-byte value is sized for secp256k1 scalars or AES-256 keys. Shares outside this shape are rejected.

### 15.4 ECIES share wrapping

Escrow nodes don't receive plaintext shares. Each share is encrypted for the target node's public key using ECIES:

```go
func EncryptForNode(plaintext []byte, nodePubKey *ecdsa.PublicKey) ([]byte, error)
func DecryptFromNode(ciphertext []byte, nodePrivKey *ecdsa.PrivateKey) ([]byte, error)
func EncryptShareForNode(share Share, nodePubKey *ecdsa.PublicKey) ([]byte, error)
func DecryptShareFromNode(encrypted []byte, nodePrivKey *ecdsa.PrivateKey) (Share, error)
```

The ECIES primitive: generate an ephemeral secp256k1 keypair, compute ECDH against the target's public key, derive an AES-256 key via SHA-256 over the shared point coordinates, encrypt with AES-256-GCM. Wire format: `[65-byte uncompressed ephemeral pubkey][12-byte nonce][ciphertext+tag]`.

Two details matter. First, scalars are padded to 32 bytes before `ScalarMult` (the default `big.Int.Bytes()` strips leading zeros, which would produce a different scalar on ~1/256 of keys and a different shared point). Second, coordinates are padded to 32 bytes before KDF input — an unpadded coordinate would yield a 31-byte KDF input on ~1/256 of exchanges, producing a different AES key than a correctly padded implementation (e.g., an HSM). These fixes are in `padScalar` and `padCoord` in `crypto/escrow/ecies.go`.

### 15.5 Blind routing and enclave attestation

The `client_side_blind` key generation mode requires the SDK to route encrypted blobs without seeing plaintext keys. `crypto/escrow/blind_routing.go` provides the interface:

```go
type EnclaveAttestation interface {
    VerifyAttestation(attestation []byte) error
    Platform() string
}
```

Implementations for Apple Secure Enclave and Android StrongBox attestations live outside the SDK (they require platform-specific verification keys). The SDK ships mock implementations (`MockAppleAttestation`, `MockAndroidAttestation`) for testing the routing path. In production, a domain application injects a real verifier.

## 16. Mode B admission (`crypto/admission`)

Mode B is the permissionless admission path. An entry is admitted if it carries a proof-of-work stamp that meets the operator's difficulty target. Mode A (fiat write credits) is the enterprise/consumer path handled at the API layer; Mode B serves independent infrastructure operators.

### 16.1 Stamp generation and verification

```go
type StampParams struct {
    EntryHash       [32]byte
    LogDID          string
    Difficulty      uint32
    HashFunc        HashFunc  // HashSHA256 or HashArgon2id
    Argon2idParams  *Argon2idParams
    Epoch           uint64
    SubmitterCommit *[32]byte
}

func GenerateStamp(p StampParams) (uint64, error)
func VerifyStamp(proof *types.AdmissionProof, entryHash [32]byte,
                 expectedLogDID string, minDifficulty uint32,
                 hashFunc HashFunc, argonParams *Argon2idParams,
                 currentEpoch uint64, acceptanceWindow uint64) error
```

`GenerateStamp` iterates nonces from 0 until it finds one whose hash has the required leading zero bits. `VerifyStamp` validates every policy knob (mode must be B, target log must match, difficulty must meet minimum, epoch must be within window) and then recomputes the hash to check difficulty. Named errors cover every failure mode: `ErrStampDifficultyOutOfRange`, `ErrStampEmptyLogDID`, `ErrStampModeMismatch`, `ErrStampTargetLogMismatch`, `ErrStampDifficultyBelowMin`, `ErrStampEpochOutOfWindow`, `ErrStampHashBelowTarget`, `ErrStampUnknownHashFunc`, `ErrStampNonceExhausted`.

### 16.2 The hash input layout

Fixed-length, deterministic:

```
entry_hash(32) || nonce(8) || did_len(2) || did(N) ||
epoch(8) || commit_present(1) || commit(32)
```

Three design points worth understanding:

**Length-prefixed DID.** The DID carries a `uint16` length prefix. Without it, a DID "ab" followed by epoch bytes that happen to spell "cd" would produce the same hash input as DID "abcd" followed by zero-epoch bytes. The length prefix eliminates this DID-boundary collision class.

**Fixed 32-byte commit slot with a separate presence byte.** An absent commit and a present-but-all-zero commit are semantically distinct (one is "unbound stamp," the other is "stamp bound to the submitter whose commit happens to be all zeros"). The presence byte distinguishes them; the 32-byte slot is zero-filled when absent. Two different semantic states, two different hash inputs.

**Domain separation salt for Argon2id.** The salt is `"ortholog-admission-v1"`, a program constant. It partitions Argon2id outputs from this protocol from outputs of any other protocol that reuses Argon2id. The v1 suffix is versioned — any change to the hash input layout requires incrementing it (v2, v3, …).

### 16.3 Epoch binding

Stamps bind to an epoch — `floor(unix_seconds / window_seconds)`. The operator accepts stamps from epochs within a window around the current epoch. This limits replay: a stamp harvested hours ago is out of window.

`EpochWindowSeconds = 300` (5 minutes) and `EpochAcceptanceWindow = 1` (±1 epoch) are the protocol defaults. Setting `EpochAcceptanceWindow = 0` **disables** the check — this is the intuitive spelling for "turn it off" and is useful in testing and in deployments that don't want replay protection. The ambiguity of "0 means strictest possible match" is avoided by making 0 mean "don't check at all."

A small guard in `CurrentEpoch`: if the system clock reads pre-Unix-epoch (a misconfiguration), the function returns 0 rather than converting the negative timestamp to a near-`MaxUint64` value. This prevents a clock-skew bug from silently passing any reasonable window check.

### 16.4 Hash function selection

Two algorithms are supported:

- **HashSHA256** — fast, appropriate when the operator's threat model doesn't require raising submitter cost relative to commodity hashing hardware.
- **HashArgon2id** — memory-hard, raises submitter cost relative to botnet infrastructure and narrows the gap between honest submitters and attackers.

`Argon2idParams` is `{Time, Memory, Threads}`. `DefaultArgon2idParams()` returns `{Time: 1, Memory: 64 MiB, Threads: 4}` — deliberately modest. Operators tune based on observed submission rates and attack patterns.

The hash function is not carried in the stamp wire format. The operator publishes its choice via its difficulty endpoint; both sides must agree out-of-band. `VerifyStamp` takes the operator's configured hash function as a parameter — submitting a stamp with one algorithm while the operator expects another produces `ErrStampHashBelowTarget` (the hash doesn't match).

### 16.5 Wire-byte aliases

The typed constants `HashSHA256`, `HashArgon2id` and `types.AdmissionModeA`, `types.AdmissionModeB` are enum values. But code that constructs the wire-format `envelope.AdmissionProofBody` needs `uint8` bytes. The SDK exports aliases so callers don't have to cast:

```go
const WireByteHashSHA256 uint8 = uint8(HashSHA256)
const WireByteHashArgon2id uint8 = uint8(HashArgon2id)
const types.WireByteModeA uint8 = uint8(types.AdmissionModeA)
const types.WireByteModeB uint8 = uint8(types.AdmissionModeB)
```

A regression test (`wire_encoding_test.go`) asserts the alias values equal the typed constant values cast to `uint8`. If a future renumbering breaks the equivalence, the SDK build breaks — not every downstream operator's integration tests. This was added after several operators independently guessed wrong about the wire encoding and only discovered the error via runtime verification failures.

### 16.6 The high-level wrapper

`lifecycle/difficulty.go` wraps the primitive with a `DifficultyConfig` struct that carries every knob operators and exchanges need:

```go
type DifficultyConfig struct {
    TargetLogDID          string
    Difficulty            uint32
    HashFunc              admission.HashFunc
    Argon2idParams        *admission.Argon2idParams
    EpochWindowSeconds    uint64
    EpochAcceptanceWindow uint64
}

func GenerateAdmissionStamp(entryHash [32]byte, cfg DifficultyConfig,
                           submitterCommit *[32]byte) (*types.AdmissionProof, error)
func VerifyAdmissionStamp(entryHash [32]byte, proof *types.AdmissionProof,
                         cfg DifficultyConfig) error
```

Most code uses these wrappers rather than `StampParams` directly. The wrapper computes the current epoch automatically from the configured window, populates `AdmissionProof` correctly, and lets callers pass one config object instead of threading many parameters. `DefaultDifficultyConfig(logDID)` returns safe starting values.


---

# Part V — Identity and Schema

## 17. DID resolution (`did/`)

The `did/` package provides W3C DID Core-compatible document resolution. Every actor in the protocol — holders, issuers, exchanges, witnesses, operators, log entities — is identified by a DID, and verifying their signatures or looking up their service endpoints means resolving that DID to a DID Document.

### 17.1 DID Documents

```go
type DIDDocument struct {
    Context            []string
    ID                 string
    VerificationMethod []VerificationMethod
    Service            []Service
    Created            *time.Time
    Updated            *time.Time
    WitnessQuorumK     int  // Ortholog extension
}
```

`VerificationMethod` entries carry public keys (hex or multibase encoded). `Service` entries describe endpoints. The SDK defines three service types:

- `OrthologOperator` — the operator's REST API base URL.
- `OrthologWitness` — a witness's endpoint.
- `OrthologArtifactStore` — an artifact store URL.

The `WitnessQuorumK` field is the K-of-N threshold for this log's witnesses. Every log publishes its own quorum in its DID Document; light clients read it once per log.

Helpers extract the pieces you need:

```go
func (d *DIDDocument) OperatorEndpointURL() (string, error)
func (d *DIDDocument) WitnessEndpointURLs() []string
func (d *DIDDocument) ArtifactStoreURL() (string, error)
func (d *DIDDocument) WitnessKeys() ([]types.WitnessPublicKey, error)
```

`WitnessKeys` iterates verification methods and returns them as `WitnessPublicKey` structs with SHA-256-derived `ID` fields.

### 17.2 Resolvers

```go
type DIDResolver interface {
    Resolve(did string) (*DIDDocument, error)
}
```

Three implementations ship with the SDK:

**`WebDIDResolver`** — resolves `did:web:` identifiers by fetching over HTTPS. `did:web:example.com` resolves to `https://example.com/.well-known/did.json`; `did:web:example.com:path:to` resolves to `https://example.com/path/to/did.json`. Size-limited (1 MB) to prevent unbounded reads.

**`CachingResolver`** — wraps any `DIDResolver` with a thread-safe TTL cache. Default TTL 5 minutes. `InvalidateCache(did)` forces refresh.

**`VendorDIDResolver`** — wraps a base resolver with vendor-method mappings. Vendor-specific DID methods (e.g., `did:court:divisionA:clerk1`) transform to standard methods before delegation. Mappings are registered at construction:

```go
resolver := did.NewVendorDIDResolver(baseResolver, []did.VendorMapping{
    {Method: "court", DomainSuffix: ".court.gov", TargetMethod: "web"},
})
```

The default transformation reverses colon-separated parts, joins with dots, and appends the domain suffix. For complex mappings, supply a `TransformFunc`. Unknown methods pass through to the base resolver unchanged.

The SDK ships no vendor mappings by default. Court-specific, hospital-specific, or agency-specific mappings belong in domain repos — same principle as "no domain vocabulary in the SDK."

### 17.3 Adapters to witness and operator packages

Two adapter types bridge `DIDResolver` into the witness and operator packages without creating circular dependencies:

```go
type DIDEndpointAdapter struct { Resolver DIDResolver }
// Satisfies witness.EndpointProvider

type DIDWitnessAdapter struct { Resolver DIDResolver }
// Satisfies witness.EndpointResolver
```

`DIDEndpointAdapter.OperatorEndpoint(logDID)` resolves the DID and returns the operator URL. `DIDWitnessAdapter.ResolveWitnessKeys(logDID)` returns witness keys and quorum K. Both satisfy interfaces in the `witness/` package through Go structural typing — no explicit implementation declaration needed.

### 17.4 Key generation and DID creation

```go
func GenerateDIDKey() (*DIDKeyPair, error)
func GenerateRawKey() (*ecdsa.PrivateKey, []byte, error)
func CreateDIDDocument(cfg CreateDIDDocumentConfig) (*DIDDocument, error)
func NewWebDID(domain string, path string) string
```

`GenerateDIDKey` produces a `did:key:` identifier with a secp256k1 key pair. Useful for ephemeral identities and tests. `CreateDIDDocument` assembles a complete document from verification methods and service endpoints. `NewWebDID` constructs a `did:web:` identifier from a domain and path, applying the slash-to-colon conversion the `did:web:` spec requires.

## 18. Schema parameters (`schema/`)

Schemas are root entities whose Domain Payloads carry the protocol parameters that govern entries referencing them. The `schema/` package provides the extractor that turns a schema entry into a typed parameter struct, plus a caching resolver for the builder.

### 18.1 The extractor interface

```go
type SchemaParameterExtractor interface {
    Extract(schemaEntry *envelope.Entry) (*types.SchemaParameters, error)
}
```

One method: given a schema entry, produce the parameters. The SDK ships `JSONParameterExtractor` which reads 13 well-known JSON fields from the Domain Payload:

| Field | Default | Purpose |
|-------|---------|---------|
| `activation_delay` | 0 | Time between publish and earliest activation |
| `cosignature_threshold` | 0 | Required cosignature count |
| `maturation_epoch` | 0 | Pre-commitment maturation window |
| `credential_validity_period` | nil | Credential expiration |
| `override_requires_witness` | false | Escrow override needs independent witness cosig |
| `migration_policy` | "strict" | How cross-version references are handled |
| `predecessor_schema` | nil | Prior version in succession chain |
| `artifact_encryption` | "aes_gcm" | AES-GCM or Umbral PRE |
| `grant_entry_required` | false | Publish commentary when granting access |
| `re_encryption_threshold` | nil | M-of-N for Umbral PRE kfrags |
| `grant_authorization_mode` | "open" | Open, restricted, or sealed |
| `grant_requires_audit_entry` | false | Audit grant issuance |
| `override_threshold` | "two_thirds" | Escrow override supermajority rule |

Unknown fields are silently ignored (forward-compatible). Malformed JSON produces a specific error. Unknown enum values for any mode field fail closed (explicit error, not silent default) — a typo in the schema should produce a loud failure, not a conservative substitution.

### 18.2 The caching resolver

```go
type CachingResolver struct { /* ... */ }
func NewCachingResolver() *CachingResolver
```

Satisfies `builder.SchemaResolver`. Given a `Schema_Ref` log position and a fetcher, it retrieves the schema entry, reads the Control Header's `CommutativeOperations` field, and caches the resolution. Cache is process-lifetime — no TTL, because schema entries are immutable (a new schema version is a new root entity with a new position).

The resolver reads only `CommutativeOperations`. Reading other parameters is the verifier's job, not the builder's — the builder only needs to know whether to apply strict OCC or Δ-window OCC. Keeping the builder's schema dependency thin minimizes the work the admission pipeline must do.

### 18.3 Shard genesis schemas

Logs that shard (split into multiple logs when an operator's log exceeds a configured size) publish genesis entries that link each shard to its predecessor. The `schema/` package defines the genesis payload type:

```go
type ShardGenesisPayload struct {
    PredecessorShard     string
    PredecessorFinalHead string  // hex-encoded SHA-256
    PredecessorFinalSize uint64
    ChainPosition        int
}

func BuildShardGenesisPayload(predShard, predHead string, predSize uint64, chainPos int) ([]byte, error)
func ParseShardGenesisPayload(data []byte) (*ShardGenesisPayload, error)
func ShardGenesisSchemaParams() *types.SchemaParameters
```

Shard chains are verified by `verifier.VerifyShardChain` (section 24). Domain applications that run multi-shard deployments use these primitives to emit and validate the linking payloads.

---

# Part VI — Lifecycle Orchestration

## 19. The universal three-phase pattern

Every consequential state transition in the protocol follows one pattern:

1. **Phase 1 — Publish.** An entry appears on the log. The SMT surfaces existence (the appropriate lane advances per the entry's path). The operation is now pending.
2. **Phase 2 — Condition.** The mandatory delay elapses. Cosignatures arrive (commentary entries with `CosignatureOf`). Contest window passes with no contest. The exchange or domain watcher monitors and collects evidence.
3. **Phase 3 — Activate.** An activation entry with `Evidence_Pointers` proving all conditions are met is published. The SMT updates `OriginTip` of the pending operation to point at the activation entry. Verifiers confirm activation by following the evidence pointers.

The pattern applies uniformly to enforcement, recovery, Tier 3 authority transfer, scope removal, and hostage override. The one exception is Tier 2 key rotation, which uses pre-authorization (pre-committed next key plus maturation epoch) in place of post-publication delay. If pre-authorization cannot be verified, the operation falls through to the three-phase lifecycle.

This uniformity is what makes the `lifecycle/` package compact. Six operation types, one shape, shared primitives.

## 20. The six lifecycle operations

### 20.1 Provisioning (`lifecycle/provision.go`)

Creating a new log means publishing: a scope entity with the creator's Authority_Set, the initial delegations, and the governing schemas. The SDK provides a single-log provisioner:

```go
func ProvisionSingleLog(cfg SingleLogConfig) (*LogProvision, error)

type LogProvision struct {
    LogDID        string
    ScopeEntry    *envelope.Entry
    Delegations   []*envelope.Entry
    SchemaEntries []*envelope.Entry
}
func (lp *LogProvision) AllEntries() []*envelope.Entry
```

The provisioner produces entries in submission order. The caller submits them to the operator's `POST /v1/entries` endpoint. The operator processes them through `builder.ProcessBatch`, creating the initial SMT leaves.

Domain-specific multi-log provisioning — e.g., a judicial network's officers/cases/parties triple — composes this function. A domain repo calls `ProvisionSingleLog` three times with per-log configuration and assembles the results into its own multi-log structure. The SDK doesn't provide multi-log provisioning because topology is a domain choice, not a protocol concern.

`ScopePayload` in the config is opaque bytes. The SDK's default is a minimal `{"log_did": cfg.LogDID}` JSON when the field is nil, but any non-nil value (including an explicit empty slice) passes through verbatim. Domain repos building on top inject their own structured payloads.

### 20.2 Scope governance (`lifecycle/scope_governance.go`)

The three-phase pattern instantiated for scope amendments. Four operations and their ordering:

```
Phase 1 (propose) → Phase 2 (collect approvals) → Phase 3 (execute)
                                                 → (for removals) time-lock → activation
```

**Proposal.**

```go
func ProposeAmendment(p AmendmentProposalParams) (*AmendmentProposal, error)
```

`AmendmentProposalParams` carries `ProposalType` (a typed enum), a description, the proposed new `AuthoritySet`, and an optional custom payload. The output is a commentary entry (no SMT impact) and metadata indicating whether the proposal requires unanimity (add/change/domain-extension) or N-1 approval (removal).

`ProposalType` is a typed enum, not a string:

```go
const (
    ProposalAddAuthority ProposalType = 1
    ProposalRemoveAuthority ProposalType = 2
    ProposalChangeParameters ProposalType = 3
    ProposalDomainExtension ProposalType = 4
)
```

Only `ProposalRemoveAuthority` routes to N-1. Everything else (including `ProposalDomainExtension` for domain-specific proposal types) requires unanimity. This is the conservative default.

**Collect approvals.**

```go
type CosignatureQuerier interface {
    QueryByCosignatureOf(pos types.LogPosition) ([]types.EntryWithMetadata, error)
}

func CollectApprovals(p CollectApprovalsParams) (*ApprovalStatus, error)
```

The querier is satisfied by the operator's query API through structural typing. `CollectApprovals` fetches all cosignature entries pointing at the proposal, filters by membership in the current `AuthoritySet`, deduplicates by signer, and counts against the threshold (all members minus proposer for unanimity; N-1 for removal). The returned `ApprovalStatus` includes `ApprovalPositions` which feed directly into the execution entry's `Approval_Pointers`.

**Execute.**

```go
func ExecuteAmendment(p ExecuteAmendmentParams) (*envelope.Entry, error)
func ExecuteRemoval(p RemovalParams) (*RemovalExecution, error)
```

`ExecuteAmendment` produces a Path C entry with `ScopePointer == TargetRoot` and `AuthoritySet` populated — the builder's lane-selection rule routes this to `OriginTip`. Immediate effect.

`ExecuteRemoval` produces a Path C entry *without* `AuthoritySet` — the builder routes this to `Authority_Tip`. The returned `RemovalExecution` carries a `TimeLock` (default 90 days, reduced to 7 days with objective triggers) and `ActivationAt` — the earliest time an activation entry may be published.

**Removal time-lock.** During the time-lock window, the targeted authority remains in the active `AuthoritySet`. They can sign Path C actions, participate in scope governance, publish contests. Only upon activation does the removal take effect. Objective triggers that reduce the window to 7 days:

- `TriggerEquivocation` — two cosigned heads at the same tree size with different roots (proof of operator misbehavior).
- `TriggerMissedSLA` — monitoring attestations of consecutive SLA failures.
- `TriggerUnauthorizedAction` — documented Path D rejections.
- `TriggerEscrowLiveness` — escrow node non-response within SLA.

Each trigger is a `LogPosition` pointing at on-log evidence. The activation entry's `EvidencePointers` reference them.

**Activation.**

```go
func ActivateRemoval(p ActivateRemovalParams) (*envelope.Entry, error)
```

Publishes a Path C entry with `AuthoritySet` populated (the set minus the removed member), `ScopePointer == TargetRoot`, and `EvidencePointers` referencing the removal execution and objective triggers. The builder's lane-selection rule routes this to `OriginTip` — the removal is now in effect.

### 20.3 Recovery (`lifecycle/recovery.go`)

Three phases, three functions:

```go
func InitiateRecovery(p InitiateRecoveryParams) (*InitiateRecoveryResult, error)
func CollectShares(p CollectSharesParams) (*CollectedShares, error)
func ExecuteRecovery(p ExecuteRecoveryParams) (*RecoveryResult, error)
```

**Initiate** publishes a commentary entry signaling intent. Escrow nodes watching the log discover it (via `ScanFromPosition` or `QueryByCosignatureOf` on the exchange's DID) and decide whether to participate.

**Collect** validates shares as they arrive. The inner call is `escrow.VerifyShare` on every share before acceptance — field tag check, index check, length check, deduplication. Invalid shares are tallied but don't block collection; recovery proceeds when M valid shares are available.

**Execute** performs reconstruction:

1. `escrow.ReconstructGF256(shares)` recovers the 44-byte key material (32-byte AES key + 12-byte nonce).
2. For each artifact CID: fetch ciphertext, re-encrypt via `ReEncryptWithGrant` (decrypt with old key, encrypt with fresh key, push new ciphertext, delete old key).
3. Build a succession entry targeting the holder's DID profile.
4. Zero the reconstructed material.

Non-fatal errors during artifact re-encryption are silently tolerated — some artifacts may be unreachable due to CAS loss. Recovery proceeds with the artifacts that survive.

**Arbitration.** When a rogue exchange contests a legitimate recovery, `EvaluateArbitration` determines whether an override is authorized:

```go
func EvaluateArbitration(p ArbitrationParams) (*ArbitrationResult, error)
```

The threshold is **schema-declared**, not hardcoded. `SchemaParameters.OverrideThreshold` carries one of `ThresholdTwoThirdsMajority`, `ThresholdSimpleMajority`, or `ThresholdUnanimity`. `OverrideThresholdRule.RequiredApprovals(N)` computes the required count. The default is two-thirds, preserving pre-threshold-refactor behavior for schemas that don't declare the field.

If `OverrideRequiresIndependentWitness` is true in the schema, the arbitration additionally requires a cosignature from an identity witness not in the scope's authority set.

### 20.4 Artifact access (`lifecycle/artifact_access.go`)

Three primitives composed into artifact access control:

**The key store.**

```go
type ArtifactKeyStore interface {
    Get(cid storage.CID) (*artifact.ArtifactKey, error)
    Store(cid storage.CID, key artifact.ArtifactKey) error
    Delete(cid storage.CID) error
}
```

Reference in-memory implementation ships with the SDK (`InMemoryKeyStore`). Production deployments back this with an HSM or KMS. The store holds AES-GCM keys only; PRE owner keys have a different lifecycle (per-identity, HSM-held) and arrive via `OwnerSecretKey` on grant params.

**Grant authorization.**

```go
type GrantAuthorizationMode uint8
const (
    GrantAuthOpen       GrantAuthorizationMode = 0
    GrantAuthRestricted GrantAuthorizationMode = 1
    GrantAuthSealed     GrantAuthorizationMode = 2
)

func CheckGrantAuthorization(params GrantAuthCheckParams) (*GrantAuthCheckResult, error)
```

Schemas declare the mode. **Open** allows any granter (no check). **Restricted** requires the granter to be in the scope's `AuthoritySet`. **Sealed** additionally requires the recipient to be in a schema-supplied authorized-recipients list. The SDK enforces the check; the domain application provides the authorized list (same trust boundary as `CandidatePositions` in `AssemblePathB` — SDK enforces membership, domain ensures correctness).

**Grant issuance.**

```go
func GrantArtifactAccess(params GrantArtifactAccessParams) (*GrantArtifactAccessResult, error)
```

Three phases internally:

1. Authorization check (if mode != open). Denied → error, no key material produced.
2. Key material production. AES-GCM path wraps the key via ECIES for the recipient. PRE path generates KFrags from `OwnerSecretKey` (the unwrapped `sk_del`, per the delegation-key isolation defense) and runs them through `PRE_ReEncrypt` to produce CFrags with DLEQ proofs.
3. Retrieval credential resolution via `RetrievalProvider.Resolve`. Optional audit entry if the schema requires it.

The result bundles everything the recipient needs: the retrieval credential, the wrapped key (AES-GCM) or CFrags and capsule (PRE), and optionally a commentary audit entry.

**Verified decryption.**

```go
func VerifyAndDecryptArtifact(params VerifyAndDecryptArtifactParams) ([]byte, error)
```

Checks ciphertext-CID match, decrypts via the schema's encryption scheme, checks plaintext-digest match. This is what consumers call to read an artifact. Integrity at both layers is enforced — bad ciphertext or tampered plaintext fails loudly.

### 20.5 Delegation keys (`lifecycle/delegation_key.go`)

Covered in section 14.3. The two functions:

```go
func GenerateDelegationKey(ownerPubKey []byte) (pkDel []byte, wrappedSkDel []byte, err error)
func UnwrapDelegationKey(wrappedSkDel []byte, ownerSecretKey []byte) ([]byte, error)
```

Called at artifact publish time (to generate per-artifact `sk_del` and wrap it for the owner's master key) and at grant time (to unwrap `sk_del` for use in `PRE_GenerateKFrags`). In production with HSMs, the unwrap happens inside the HSM; the software helper exists for testing and for software-only deployments.

### 20.6 Admission stamps (`lifecycle/difficulty.go`)

Covered in section 16.6. The high-level wrapper over `crypto/admission`.

---

# Part VI.5 — Building a Domain Network on Ortholog

This is the chapter a domain builder comes for. Sections 21 and 22 cover the concept and the worked example.

## 21. The shape of a domain network

A domain network is a deployment of Ortholog where:

- **The protocol layer is unchanged.** The domain doesn't fork the SDK, doesn't add fields to the Control Header, doesn't introduce new entry paths beyond A/B/C/commentary/new-leaf. Every domain entry is a standard Ortholog entry.
- **Domain behavior lives entirely in payloads and schemas.** The Domain Payload carries the domain's data model — a JSON document conforming to a schema published as a prior entry in the log. Domain-specific fields (license number, jurisdiction, license class, examiner ID) never touch the Control Header.
- **The domain provides three things the SDK doesn't:** a schema catalog (the JSON schemas describing each record type, published as schema entries in the log itself), a DID resolution policy (who is allowed to publish, who delegates to whom, what authority sets look like), and an operator network (at minimum one log operator; in practice a federation across jurisdictional or organizational boundaries).

### 21.1 What the SDK gives you for free

- Entry serialization and canonical hashing (`core/envelope`, `crypto/hash`)
- Two-lane SMT and the builder pipeline (`core/smt`, `builder/`)
- Authority verification with delegation, scope governance, contests (`verifier/`)
- Witness cosignature and equivocation detection (`witness/`)
- Artifact encryption and key escrow (`crypto/artifact`, `crypto/escrow`)
- Lifecycle orchestration for provisioning, governance, recovery (`lifecycle/`)
- Admission control and stamp generation (`crypto/admission`, `lifecycle/difficulty.go`)
- DID resolution (`did/`) and schema parameter extraction (`schema/`)
- HTTP adapters for operator and artifact store (`log/`, `storage/`)

### 21.2 What the domain must build

**Payload schemas.** Define record types — for a licensing board: `license_issuance`, `license_suspension`, `license_transfer`, `license_renewal`. Publish them as schema entries in the log via `builder.BuildSchemaEntry`. Subsequent entries reference them via `SchemaRef` in the Control Header.

**A DID hierarchy.** Decide who the root authorities are, how delegation flows downward, how scope authority sets are constituted. The SDK supports arbitrary topologies — the domain chooses. For a licensing board: the board is the scope authority; it delegates to field examiners who delegate to inspectors; licensees are root entities governed by the scope.

**Operator deployment.** Run an `ortholog-operator` instance configured with the log's DID, the schema catalog (or a bootstrap pointer), the witness set with K-of-N quorum, and storage backends (Postgres for index, Tessera for entry bytes, S3 or IPFS for artifacts). The operator is a separate binary; the SDK is the library it depends on.

**Domain-specific verification logic.** The SDK verifies protocol correctness (signatures valid, authority established, chain consistent). The domain decides semantic correctness (this license is valid for this purpose, this transfer respects jurisdictional rules). Domain verification is a thin layer on top of `verifier/` — you read entities via the SDK's evaluators, then apply domain rules to the payloads.

**Federation policy** (for multi-operator networks). When a licensing network spans multiple states or agencies, the domain decides which logs trust each other (cross-log evidence pointers and anchor entries), how appellate or supervisory authority flows across logs, and how recovery proceeds when keys are lost (which operators participate in escrow).

## 22. Worked example: a professional licensing board

A state licensing board regulates a profession — say, architecture. Licensees are practitioners; the board issues, suspends, and transfers licenses. Deploy Ortholog as the substrate and the board's records are append-only, cryptographically verifiable, and auditable by anyone with the log's DID.

### 22.1 The topology

**One log per state board.** Its DID is `did:web:architecture.ca.gov:licensing`. The operator is run by the board's IT contractor. Witnesses are the board, the state archives office, and two independent third-party witness operators (quorum K=3 of N=4).

**Authority structure.** The scope authority set is the board commissioners (five DIDs). Commissioners delegate to "licensing officers" (staff) who process applications and issue licenses. Enforcement actions — suspensions, revocations — flow through the scope's Path C with full commissioner cosignatures.

**Schemas.** Four schemas published at provisioning time: `architect_license_v1`, `license_suspension_v1`, `license_transfer_v1`, `license_renewal_v1`. Each carries `activation_delay`, `cosignature_threshold`, `override_threshold`, and `credential_validity_period` (two years for architect licenses). The suspension schema declares `override_requires_witness: true` — overrides of a contested suspension require an identity-witness cosignature.

**Licensees** are root entities. Each license is its own SMT leaf, identified by the log position of the issuance entry. The DID of the licensee is registered in a vendor-DID mapping the board maintains off-log, with the mapping escrowed via `exchange/identity/mapping_escrow.go` (section 28).

### 22.2 License issuance — Path A

The field examiner verifies an applicant, the supervising officer approves, and the licensing officer publishes an issuance entry. Concretely:

1. The officer constructs a Domain Payload — a JSON document conforming to `architect_license_v1`. Fields: license number, licensee DID, jurisdiction code, license class, date of issuance, expiration date, examiner ID, supervisor's sign-off hash.
2. The officer calls `builder.BuildRootEntity` with `SignerDID = officer's DID`, the payload, and `SchemaRef` pointing at the schema entry's log position.
3. The operator admits the entry; `ProcessBatch` classifies it as `PathResultNewLeaf` (no `TargetRoot`, `AuthorityPath` set). A new leaf is created with both tips pointing at the issuance entry's position.
4. The officer cosigns the issuance through `builder.BuildCosignature` if the schema's `cosignature_threshold` is nonzero (typically it isn't for routine issuance; requiring a second officer's cosig is a policy choice the schema encodes).

The license is now in the SMT. A verifier asking "is license #AR-12345 currently valid?" computes the SMT key, fetches the leaf via `verifier.EvaluateOrigin`, and reads the tip entry.

### 22.3 License suspension — Path C

A disciplinary committee finds grounds for suspension. The board votes. Four of five commissioners approve. The fifth is absent; the board has a quorum.

The flow instantiates the three-phase lifecycle:

1. **Publish.** A commissioner publishes the suspension via `builder.BuildEnforcement`:
   - `SignerDID = publishing commissioner's DID`
   - `TargetRoot = license's issuance position`
   - `AuthorityPath = AuthorityScopeAuthority`
   - `ScopePointer = board scope's position`
   - `SchemaRef = license_suspension_v1's position`
   - `PriorAuthority = license's current Authority_Tip`
   - Domain Payload carries the findings, effective date, and appeal rights.
   
   The builder classifies this as PathC and advances `Authority_Tip`. The license's `Origin_Tip` is unchanged — the credential's content is the same; only the enforcement state changed.

2. **Condition.** The schema's `activation_delay` (30 days for suspensions) begins counting. The four other commissioners cosign via `builder.BuildCosignature` pointing at the suspension entry. If the licensee contests, they publish a contest entry (another commentary with `CosignatureOf = suspension position`). If there's no contest and all four cosigs arrive, the conditions are met.

3. **Activate.** After 30 days, the board publishes an activation entry. `EvidencePointers` reference each cosignature and (if relevant) the passage of the contest window. The activation entry's `TargetRoot = license`, `TargetIntermediate = suspension entry`. Path compression updates both leaves — suspension becomes visible in O(1) from either direction.

Now `verifier.EvaluateAuthority` on the license returns an active constraint (the activated suspension). `verifier.EvaluateConditions` on the suspension returns `AllMet: true`. Domain verification layers read the suspension's payload to surface the specific grounds.

### 22.4 License transfer — Path A

An architect moves from California to Nevada. California's board records a transfer entry:

1. Licensing officer constructs a `license_transfer_v1` Domain Payload recording the destination jurisdiction, effective date, and reciprocity authority.
2. Calls `builder.BuildAmendment` with `SignerDID = officer's DID`, `TargetRoot = license issuance position`, payload, `SchemaRef = license_transfer_v1`.

Because the officer is Path B (they hold delegated authority from the board scope, not Path A against the license — the license was issued under the scope, not by the officer personally), they actually use `builder.BuildPathBEntry` after calling `builder.AssemblePathB` to construct the delegation chain: board → officer's supervisor → officer. The chain connects back to the board's signer.

This is where domain design matters: the board could have set up delegations so that officers sign issuances in their own name (Path A thereafter for amendments) or so that the board signs issuances and officers act by delegation (Path B for amendments). Both are valid Ortholog topologies. The choice affects how delegations revoke: if the officer later leaves, revoking their delegation disables their Path B authority on every license they'd handle — which may be exactly the point, or may not.

For Nevada to recognize the license, Nevada's board (a separate Ortholog log) receives cross-log evidence. California publishes an anchor entry on Nevada's log committing to California's tree head at the transfer entry's sequence. Nevada verifies the transfer via `verifier.VerifyCrossLogProof` (section 24), which confirms the transfer entry is included in a California tree head Nevada has anchored.

### 22.5 Key recovery — a commissioner's HSM fails

A commissioner's signing key is lost. The scope's authority set now has a "dead" member — the remaining four commissioners cannot publish Path C actions if the schema requires full quorum, and the dead commissioner can't sign their own key rotation.

The lifecycle is N-1 removal under the scope governance flow (section 20.2):

1. A surviving commissioner publishes a removal proposal via `lifecycle.ProposeAmendment` with `ProposalType = ProposalRemoveAuthority` targeting the dead commissioner's DID.
2. The other three surviving commissioners publish cosignature entries — four of five total.
3. `lifecycle.CollectApprovals` confirms N-1 is met. A surviving commissioner publishes the removal execution via `lifecycle.ExecuteRemoval`. This advances `Authority_Tip` on the scope and starts the time-lock.
4. Default time-lock is 90 days. If the board produces objective evidence (e.g., monitoring attestations of consecutive SLA failures on the dead commissioner's signing endpoint), the time-lock reduces to 7 days.
5. During the time-lock, the dead commissioner is still formally in the authority set but cannot sign. If they somehow sign (key recovered, custody dispute), they can contest the removal.
6. After the time-lock, a surviving commissioner publishes the activation entry via `lifecycle.ActivateRemoval` with the new `AuthoritySet` (four commissioners). `Origin_Tip` of the scope advances.

A replacement commissioner is onboarded via a symmetric process (`ProposalType = ProposalAddAuthority`, unanimous among surviving members). The scope is healthy again.

### 22.6 Artifact handling — a disciplinary file

The board's investigation of the suspended architect produces a file — investigation notes, witness statements, exhibits. The file is sensitive; the schema declares `artifact_encryption: "umbral_pre"` because access needs to be grantable.

1. The investigator encrypts the file via `lifecycle.GenerateDelegationKey` followed by `artifact.PRE_Encrypt`. The capsule goes in the suspension entry's Domain Payload; the wrapped `sk_del` goes in the board's artifact key store (keyed by CID); the ciphertext goes in the board's content store.
2. Later, the licensee's attorney requests the file under discovery. The board grants access via `lifecycle.GrantArtifactAccess` with `RecipientPubKey = attorney's public key`, `OwnerSecretKey = unwrapped sk_del`, and `GrantAuthorizationMode = GrantAuthRestricted` (the attorney is added to the authorized-recipients list by the disciplinary committee's order).
3. The board has M=3 re-encryption nodes (staff members across departments). Each runs `artifact.PRE_ReEncrypt` on its kfrag against the capsule. Three CFrags arrive back.
4. The attorney calls `lifecycle.VerifyAndDecryptArtifact` with the CFrags and capsule. The file decrypts. Ciphertext integrity is verified against the CID in the suspension entry; plaintext integrity is verified against the content digest.

The board's HSM never sees plaintext. The re-encryption nodes never see plaintext. If three nodes collude with the attorney, they extract only `sk_del` — the per-artifact delegation key — not the board's master signing key.

### 22.7 What verification looks like on this deployment

A civil court needs to confirm the suspension is active. The clerk:

1. Obtains the license's log position from the board's public record.
2. Calls `verifier.EvaluateOrigin(leafKey, leafReader, fetcher)` → confirms the license's origin state is "active" (no revocation).
3. Calls `verifier.EvaluateAuthority(leafKey, leafReader, fetcher, extractor)` → receives the list of active constraints. The suspension is in the list.
4. Calls `verifier.EvaluateContest(suspensionPos, fetcher, leafReader, extractor)` → confirms no unresolved contest.
5. Calls `verifier.EvaluateConditions(EvaluateConditionsParams{...})` → confirms the suspension's activation conditions were met.
6. Optionally, domain-specific logic reads the suspension's Domain Payload to surface the findings.

None of this requires the clerk to run an operator or maintain the full log history. A witness-verified tree head plus on-demand entry fetches via `log.HTTPEntryFetcher` is enough. The board publishes its witness set via its DID Document, so a fresh client can bootstrap via `verifier.AnchorLogSync` or `verifier.HardcodedGenesis` and start verifying within seconds.

This is the whole point. The domain builds four schemas and a commissioner DID hierarchy. The SDK handles the rest. What the public sees — an append-only record they can verify without trusting the board — falls out of the protocol.

---

# Part VII — Verification

Verification is reading SMT state without mutating it. Section 23 covers the 90% case — the evaluators most domain verification flows call on every credential read. Section 24 covers the advanced tools you reach for when cross-log verification, fraud proofs, or bootstrap trust establishment matters.

## 23. The 90% case: reading entity state

### 23.1 Origin evaluation — is the entity active?

```go
func EvaluateOrigin(leafKey [32]byte, leafReader smt.LeafReader,
                   fetcher EntryFetcher) (*OriginEvaluation, error)
```

O(1). One leaf read, one entry fetch. Returns an `OriginEvaluation` with a classified state:

- `OriginOriginal` — the entity's `Origin_Tip` is still the root entity entry. Never been amended.
- `OriginAmended` — `Origin_Tip` advanced to an entry whose `TargetRoot` resolves back to this leaf. The entity was modified via Path A, Path B, or a scope amendment.
- `OriginRevoked` — `Origin_Tip` advanced to an entry that does not target this leaf (revocation, deletion, or tip points at a missing entry).
- `OriginSucceeded` — reserved for succession chains where the entity was superseded.
- `OriginPending` — reserved for activation-delay evaluation that the caller performs separately via `EvaluateConditions`.

The evaluator returns the `TipEntry` and `TipPosition`, and if the tip entry uses path compression (`TargetIntermediate` set), it reports the `IntermediatePosition` so the caller can drill down.

This is the fastest path to "is this credential currently valid?" — a single leaf read and entry fetch, deterministic and replayable anywhere.

### 23.2 Authority evaluation — what constraints are active?

```go
func EvaluateAuthority(leafKey [32]byte, leafReader smt.LeafReader,
                      fetcher EntryFetcher,
                      extractor schema.SchemaParameterExtractor) (*AuthorityEvaluation, error)
```

Walks the `Prior_Authority` chain backward from `Authority_Tip` and classifies each entry as active, pending (within activation delay), or overridden. Returns an `AuthorityEvaluation`:

```go
type AuthorityEvaluation struct {
    ActiveConstraints []ConstraintEntry
    PendingCount      int
    ChainLength       int
    UsedSnapshot      bool
}
```

Three termination conditions short-circuit the walk:
- `Prior_Authority == TargetRoot` (base case — no prior).
- An authority snapshot entry is encountered — its `Evidence_Pointers` contain the full active constraint set, no further walking needed.
- An `Authority_Skip` pointer is set — traversal jumps to the skip target (O(log A) overall).

A safety guard caps the walk at 1000 entries. Any chain exceeding that is either corrupt data or a denial-of-service attempt; the evaluator breaks out and returns what it has.

Classification uses `schema.SchemaParameterExtractor` to read each entry's activation delay. If `now < entry_log_time + activation_delay`, the constraint is pending, not active. Pending constraints count toward `PendingCount` but don't appear in `ActiveConstraints`.

The most recent non-pending entry at each level is active; older entries at the same level are overridden unless they came from a snapshot (snapshot entries are all active by definition — the snapshot already decided which constraints apply).

### 23.3 Condition evaluation — is a pending operation ready?

```go
func EvaluateConditions(p EvaluateConditionsParams) (*ConditionResult, error)
func CheckActivationReady(p EvaluateConditionsParams) (bool, error)
```

Four conditions, all schema-driven:
1. **Activation delay** — `entry_log_time + ActivationDelay ≤ now`.
2. **Cosignature threshold** — distinct valid cosignatures ≥ `CosignatureThreshold` (excluding self-cosignature from the entry's own signer).
3. **Maturation epoch** — for key rotation, `entry_log_time + MaturationEpoch ≤ now`.
4. **Credential validity period** — for credentials with expiry, `now < entry_log_time + CredentialValidityPeriod`.

Each condition evaluates to one of `ConditionMet`, `ConditionPending`, `ConditionNotApplicable`, or `ConditionFailed`. The overall result's `AllMet` is true only when every applicable condition is Met (none Pending, none Failed). `EarliestActivation` is the latest pending `MetAt` time — the moment all conditions will be met.

The caller supplies the cosignature entries (pre-fetched via `OperatorQueryAPI.QueryByCosignatureOf`). This keeps the evaluator pure — it evaluates given data, it doesn't fetch data. Monitoring services call `CheckActivationReady` in tight loops to decide when to publish activation entries.

### 23.4 Contest and override evaluation

```go
func EvaluateContest(pendingPos types.LogPosition, fetcher EntryFetcher,
                    leafReader smt.LeafReader,
                    extractor schema.SchemaParameterExtractor) (*ContestResult, error)
```

Determines whether a pending operation has been contested and whether the contest has been overridden. Three outcomes:

- **No contest** — `OperationBlocked: false`, nil positions. Operation unblocked.
- **Contest, no override** — `OperationBlocked: true`, `ContestPos` set. Operation blocked.
- **Contest with valid override** — `OperationBlocked: false`, both positions set. Operation unblocked.

The evaluator walks the entity's `Authority_Tip` chain looking for entries with `CosignatureOf == pendingPos` (contests). If found, it scans for override entries that reference the contest in their `EvidencePointers` and carry enough distinct signers to meet the schema-declared threshold.

The threshold is schema-driven via `OverrideThresholdRule`. `ThresholdTwoThirdsMajority` (default) requires ⌈2N/3⌉ approvals. `ThresholdSimpleMajority` requires ⌈N/2⌉+1. `ThresholdUnanimity` requires all N. The rule is read from the pending entry's `SchemaRef` — different schemas can carry different rules.

If `OverrideRequiresIndependentWitness` is true in the schema, the evaluator additionally looks for a cosignature from a signer not in the scope's `AuthoritySet`. This is the "identity witness" requirement — an external observer who didn't have a stake in the contested operation.

### 23.5 Key rotation evaluation

```go
func EvaluateKeyRotation(rotationPos types.LogPosition, fetcher EntryFetcher,
                        leafReader smt.LeafReader,
                        extractor schema.SchemaParameterExtractor) (*RotationEvaluation, error)
```

Classifies a rotation as Tier 2 (pre-committed + matured, immediate) or Tier 3 (activation delay + contest window + identity witness required).

The algorithm:
1. Fetch the rotation entry, extract the target DID profile position.
2. Fetch the DID profile, read `next_key_hash` from its Domain Payload.
3. Compute the rotation's new key hash (from the `new_key_hash` field or hash of `new_public_key`).
4. If hashes match AND `profile_log_time + maturation_epoch ≤ rotation_log_time`: Tier 2.
5. Otherwise: Tier 3. Delegate to `EvaluateContest` for contest/override status.

`RotationEvaluation.EffectiveAt` is nil for Tier 2 (immediate) and set to `rotation_log_time + activation_delay` for Tier 3. `ContestResult` is populated for Tier 3 only.

These five evaluators — Origin, Authority, Conditions, Contest, KeyRotation — are the read-side of the protocol. They cover what domain verification flows need 90% of the time.

## 24. Advanced verification

Section 23's evaluators work on a single log. When verification spans logs, requires adversarial checks against operator misbehavior, or needs to bootstrap trust from scratch, the advanced tools apply.

### 24.1 Cross-log compound proofs

```go
type CrossLogProof struct {
    SourceEntry         types.LogPosition
    SourceEntryHash     [32]byte
    SourceTreeHead      types.CosignedTreeHead
    SourceInclusion     types.MerkleProof
    AnchorEntry         types.LogPosition
    AnchorEntryHash     [32]byte
    AnchorTreeHeadRef   [32]byte
    LocalTreeHead       types.CosignedTreeHead
    LocalInclusion      types.MerkleProof
}

func VerifyCrossLogProof(proof types.CrossLogProof,
                        sourceWitnessKeys []types.WitnessPublicKey,
                        sourceQuorumK int,
                        blsVerifier signatures.BLSVerifier) error

func BuildCrossLogProof(sourceRef, anchorRef types.LogPosition,
                       fetcher EntryFetcher,
                       sourceProver, localProver MerkleProver,
                       sourceHead, localHead types.CosignedTreeHead) (*types.CrossLogProof, error)
```

The proof bundles everything needed to verify that an entry in a foreign log is committed to a locally-anchored state. Five checks run in order:

1. `SourceEntryHash` is non-zero.
2. `SourceInclusion` proof verifies against `SourceTreeHead.RootHash`.
3. `SourceTreeHead` has valid K-of-N witness cosignatures.
4. `AnchorTreeHeadRef` matches `hash(SourceTreeHead)` — the anchor entry is genuinely anchoring this specific tree head.
5. `LocalInclusion` proof verifies against `LocalTreeHead.RootHash` — the anchor entry is in the local log.

All five must pass. Each failure mode has a specific error (`ErrSourceInclusionFailed`, `ErrSourceHeadInvalid`, `ErrAnchorMismatch`, `ErrLocalInclusionFailed`) for diagnostics.

`BuildCrossLogProof` assembles the proof. The caller provides positions, a fetcher that works on both logs, Merkle provers for each log, and both logs' cosigned tree heads. The result packages everything into one verifiable object — roughly 2.1 KB regardless of how many entries you're proving.

### 24.2 Fraud proofs over derivation commitments

```go
func VerifyDerivationCommitment(
    commitment types.SMTDerivationCommitment,
    fetcher EntryFetcher,
    schemaRes builder.SchemaResolver,
    logDID string,
) (*FraudProofResult, error)
```

A state-map operator publishes a `SMTDerivationCommitment` per batch:

```go
type SMTDerivationCommitment struct {
    LogRangeStart types.LogPosition
    LogRangeEnd   types.LogPosition
    PriorSMTRoot  [32]byte
    PostSMTRoot   [32]byte
    Mutations     []types.LeafMutation
    MutationCount uint32
}
```

`VerifyDerivationCommitment` replays the batch from scratch: build a fresh tree, seed it with `OldOriginTip` and `OldAuthorityTip` from each mutation, verify the seeded root matches `PriorSMTRoot`, fetch the entries in the range, run `builder.ProcessBatch`, compare the replay's mutations and root against the commitment's.

Any divergence produces `FraudProof` entries — O(1) evidence per incorrect mutation (just the leaf key, expected, and actual). A committed mutation missing from the replay is fraud. A replay mutation missing from the commitment is fraud. A root mismatch with no per-leaf divergence is fraud (with no per-leaf proofs — all mutations are individually correct but the commitment asserts a wrong post-root).

This is the mechanism that keeps state-map operators honest. Any party can run the verification; the evidence is cryptographic; the witnesses' cosignature on a fraudulent commitment becomes the slashing evidence on any economic layer the consumer builds.

### 24.3 Bootstrap methods

A new light client must establish trust in the log's witness set before verifying anything. Three methods:

```go
func HardcodedGenesis(genesisSet []types.WitnessPublicKey,
                     rotations []types.WitnessRotation,
                     quorumK int, latestHead types.CosignedTreeHead,
                     blsVerifier signatures.BLSVerifier) (*BootstrapResult, error)

func AnchorLogSync(anchorLogDID string, client *witness.TreeHeadClient,
                  anchorWitnessKeys []types.WitnessPublicKey, anchorQuorumK int,
                  blsVerifier signatures.BLSVerifier) (*BootstrapResult, error)

func TrustOnFirstUse(head types.CosignedTreeHead,
                    fetchedAt time.Time) (*BootstrapResult, error)
```

**HardcodedGenesis.** The genesis witness set is compiled into the binary. Walk the rotation chain (`witness.VerifyRotationChain`) from genesis to current set, verify each rotation's K-of-N signatures by the set that preceded it. Then verify the latest head against the current set. This is the strongest method — an attacker cannot substitute the genesis set without replacing the binary.

**AnchorLogSync.** Fetch a tree head from a trusted anchor log. The anchor log's witness keys and quorum must be provided (typically from a prior `HardcodedGenesis` bootstrap of the anchor log itself). Used when a new domain log trusts an existing anchor log's witness infrastructure — common in federated deployments where an anchor consortium vouches for spoke logs.

**TrustOnFirstUse.** Accept the first tree head seen and pin it. No cryptographic verification. Suitable for development, testing, and scenarios where first contact is assumed secure. The weakest method; subsequent updates must be consistent with the pinned head.

All three return a `BootstrapResult` with the witness set, quorum K, verified head, and a trust-anchor hash. From that point, ongoing verification uses standard witness-cosignature primitives.

### 24.4 Shard chain verification

When a log shards, each shard's genesis entry (position 0) carries a pointer to its predecessor. `VerifyShardChain` walks the chain and checks every link:

```go
func VerifyShardChain(shards []ShardInfo) (*ShardChainResult, error)
func VerifyShardGenesis(genesisBytes []byte, expectedPredecessor string,
                       expectedFinalSize uint64,
                       expectedFinalHead types.TreeHead) error
```

Checks that each shard's `PredecessorShard` matches the prior shard's ID, `PredecessorFinalSize` matches the prior shard's entry count, `PredecessorFinalHead` matches the hash of the prior shard's final cosigned tree head, and `ChainPosition` is sequential.

Any broken link is fatal — the result carries `BrokenAt` with the first broken index. Domain applications that operate multi-shard deployments call this as part of their verification flow.

### 24.5 Schema succession walking

```go
func WalkSchemaChain(pinnedRef types.LogPosition, fetcher EntryFetcher,
                    extractor schema.SchemaParameterExtractor) (*SchemaChain, error)
func EvaluateMigration(chain *SchemaChain, sourcePos, targetPos types.LogPosition) *MigrationResult
```

Schemas evolve — a v2 schema references v1 via `predecessor_schema`. `WalkSchemaChain` walks the chain backward, building the full version history oldest-first. `EvaluateMigration` checks whether a reference from an entry governed by one schema version to an entry governed by another is allowed under the effective migration policy:

- **Strict** — references only allowed within the same schema version.
- **Forward** — newer schema can reference older (`source.ChainIndex >= target.ChainIndex`).
- **Amendment** — cross-version references allowed but require explicit per-entry migration.

Domain onboarding flows check compatibility before adopting a new schema version. Verifiers check that a credential issued under an older schema is still valid under the current version.

### 24.6 Delegation tree walking

```go
func WalkDelegationTree(p WalkDelegationTreeParams) (*DelegationTree, error)
func FlattenTree(tree *DelegationTree) []*DelegationNode
func LiveDelegations(tree *DelegationTree) []*DelegationNode
```

Unlike `VerifyDelegationProvenance` which walks a specific chain of `DelegationPointers` for one entry, `WalkDelegationTree` discovers all delegations issued by a signer and builds the full tree breadth-first. Useful for domain administration tools — "show me every officer who currently holds delegated authority from this court," "audit the delegation structure for this licensing board."

Max depth is the protocol's 3. Cycle detection: if a `DelegateDID` appears as a signer at a deeper level in its own ancestor chain, the branch is pruned.

### 24.7 Delegation provenance for a specific chain

```go
func VerifyDelegationProvenance(delegationPointers []types.LogPosition,
                               fetcher EntryFetcher,
                               leafReader smt.LeafReader) ([]DelegationHop, error)
```

The per-chain counterpart to tree walking. Given the delegation pointers from a specific entry's Control Header, verify each hop's liveness and return structured `DelegationHop` results: position, signer DID, delegate DID, `IsLive` flag, and `RevokedAt` if the delegation has been amended or revoked.

This is what the builder uses internally for Path B acceptance (though it returns pass/fail, not structured results). Verifiers use the structured version to explain chain status to humans.

---

# Part VIII — Witness Infrastructure

Witness infrastructure is two conceptual halves. Verification — checking that a tree head carries K-of-N valid cosignatures from a known witness set. And operations — fetching tree heads, detecting equivocation, managing staleness, validating rotations. Section 25 covers verification; section 26 covers operations.

## 25. Witness verification

### 25.1 K-of-N cosignature verification

```go
func VerifyTreeHead(head types.CosignedTreeHead,
                   witnessKeys []types.WitnessPublicKey,
                   quorumK int,
                   blsVerifier signatures.BLSVerifier) (*VerifyResult, error)
```

The primary verification entry point. Dispatches on `head.SchemeTag`:

- `SchemeECDSA` — verifies each signature independently against the known witness public keys.
- `SchemeBLS` — delegates aggregate verification to the injected `BLSVerifier`.

Returns `VerifyResult` with the valid count, total count, quorum K, and per-signer details. An error return means quorum wasn't met (`ErrInsufficientWitnesses`) or structural input was bad (nil witness set, no signatures, quorum larger than set).

The result type includes per-signer verification status — useful for identifying which witnesses failed and why, not just "3 of 5 valid." Downstream monitoring can track per-witness reliability over time.

### 25.2 Verification via DID resolution

```go
type EndpointResolver interface {
    ResolveWitnessKeys(logDID string) ([]types.WitnessPublicKey, int, error)
}

func VerifyTreeHeadWithResolution(head types.CosignedTreeHead, logDID string,
                                 resolver EndpointResolver,
                                 blsVerifier signatures.BLSVerifier) (*VerifyResult, error)
```

Higher-level wrapper: given a log DID and a resolver, discover the witness set and quorum from the log's DID Document, then verify. Satisfied by `did.DIDWitnessAdapter` through structural typing.

This is what cross-log verification uses. The source log's witness set is discovered on demand via DID resolution; the local log's witness set is cached from prior bootstrap.

### 25.3 Witness set rotation

Witness sets change over time. A rotation is a message signed by the current set that authorizes a new set:

```go
type WitnessRotation struct {
    CurrentSetHash    [32]byte
    NewSet            []types.WitnessPublicKey
    SchemeTagOld      byte
    SchemeTagNew      byte
    CurrentSignatures []types.WitnessSignature
    NewSignatures     []types.WitnessSignature
}

func VerifyRotation(rotation types.WitnessRotation,
                   currentSet []types.WitnessPublicKey, quorumK int,
                   blsVerifier signatures.BLSVerifier) ([]types.WitnessPublicKey, error)

func VerifyRotationChain(genesisSet []types.WitnessPublicKey,
                        rotations []types.WitnessRotation, quorumK int,
                        blsVerifier signatures.BLSVerifier) ([]types.WitnessPublicKey, error)
```

`VerifyRotation` checks:

1. Non-empty new set and current signatures.
2. `rotation.CurrentSetHash` matches `ComputeSetHash(currentSet)`.
3. Current signatures verify K-of-N by the current set.
4. If `SchemeTagNew != SchemeTagOld` (scheme transition), `NewSignatures` also verify K-of-N by the **new** set under the new scheme — this is the dual-sign bridge.

The dual-sign mechanism is how witness sets migrate from ECDSA to BLS (or any future scheme) atomically. Light clients processing the rotation receive proof from both the old set (using old scheme) and the new set (using new scheme); after the rotation, only the new scheme is accepted.

`VerifyRotationChain` walks from genesis through N rotations, validating each step against the set produced by the prior step. Used by `verifier.HardcodedGenesis` to derive the current witness set from a compiled-in genesis.

`ComputeSetHash` is deterministic and used for rotation message binding. If two implementations of the SDK compute different set hashes from the same key list, rotation verification breaks. The implementation: hash the concatenation of each key's `ID` (32 bytes) and `PublicKey` bytes, in list order.

## 26. Operational witness properties

### 26.1 Tree head fetching and caching

```go
func NewTreeHeadClient(endpoints EndpointProvider, cfg TreeHeadClientConfig) *TreeHeadClient
func (tc *TreeHeadClient) FetchLatestTreeHead(logDID string) (types.CosignedTreeHead, time.Time, error)
func (tc *TreeHeadClient) FetchFromURL(url string) (types.CosignedTreeHead, time.Time, error)
func (tc *TreeHeadClient) CachedHead(logDID string) (types.CosignedTreeHead, time.Time, bool)
func (tc *TreeHeadClient) InvalidateCache(logDID string)
```

The client fetches tree heads from operators over HTTP (endpoint resolution via the injected `EndpointProvider`, typically `did.DIDEndpointAdapter`). Results are cached per log DID with a TTL (default 30s).

On cache miss, it resolves the log's operator endpoint, issues `GET /v1/tree/head`, parses the JSON response, and updates the cache. If the operator is unreachable, it falls back to the log's witness endpoints — witnesses also serve tree heads, and this gives liveness during operator outages.

`FetchFromURL` bypasses the cache and targets a specific URL. Used for equivocation detection — comparing an operator's tree head against individual witnesses' tree heads requires fresh fetches against each endpoint, not a shared cache.

### 26.2 Staleness

Different use cases need different freshness:

```go
type StalenessConfig struct { MaxAge time.Duration }

var StalenessWallet = StalenessConfig{MaxAge: 1 * time.Hour}
var StalenessMonitoring = StalenessConfig{MaxAge: 60 * time.Second}
var StalenessRealtime = StalenessConfig{MaxAge: 15 * time.Second}
var StalenessNone = StalenessConfig{MaxAge: 0}

func CheckFreshness(fetchedAt time.Time, now time.Time,
                   cfg StalenessConfig) (*FreshnessResult, error)
func CheckFreshnessNow(fetchedAt time.Time,
                      cfg StalenessConfig) (*FreshnessResult, error)
```

Mobile credential wallets tolerate 1-hour staleness (background refresh). Real-time monitoring wants 60 seconds. Bridge contracts need 15 seconds. Archival verification disables the check entirely (`MaxAge: 0` means no check).

`CheckFreshness` is pure — it compares `fetchedAt` to `now` against `MaxAge`. Callers pass `time.Now().UTC()` for live code or a fixed time for deterministic tests. `CheckFreshnessNow` is the convenience wrapper that calls `time.Now().UTC()` internally.

### 26.3 Equivocation detection

```go
func DetectEquivocation(headA, headB types.CosignedTreeHead,
                       witnessKeys []types.WitnessPublicKey,
                       quorumK int,
                       blsVerifier signatures.BLSVerifier) (*EquivocationProof, error)
```

Two cosigned tree heads at the same tree size but with different root hashes, both carrying valid K-of-N signatures, are cryptographic proof of operator misbehavior. Equivocation proofs are unforgeable — producing one requires compromising K-of-N witness keys.

Three outcomes:
- Same roots → `(nil, nil)` — no equivocation.
- Different tree sizes → `(nil, ErrDifferentSizes)` — not equivocation, just different states.
- Same size, different roots, both valid → `(*EquivocationProof, nil)` — proven equivocation.

If either head fails verification, no proof is generated. A head with invalid signatures proves nothing about operator behavior.

The `EquivocationProof` captures both heads and the valid signature counts. It's consumed by `lifecycle/scope_governance.go` as an objective trigger for N-1 scope removal (the offending operator loses their scope authority on 7-day time-lock instead of 90), and by external monitoring services that publish alerts or drive economic slashing on whatever economic layer the deployment has built.

---

# Part IX — Integration Boundaries

Section 27 covers the injection contracts that make the SDK work with arbitrary backends. Section 28 covers vendor DID mapping with double-blind escrow — a subtle piece that no one would figure out from the code alone.

## 27. The injection contracts

The SDK is transport-agnostic by default. Every place where state crosses a process boundary, the SDK defines an interface and takes an injected implementation. Four contracts matter.

### 27.1 EntryFetcher — read entries by position

Defined three times with the same shape, one in each of `builder/`, `verifier/`, and `lifecycle/`. They are structurally identical and any implementation satisfies all three without explicit declaration.

```go
type EntryFetcher interface {
    Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error)
}
```

The contract: return `(nil, nil)` for not-found (normal condition during chain walks), return a non-nil error only for transport failures the caller should propagate, never fetch from foreign logs (builder's locality rule). Returns canonical bytes plus operator-assigned metadata (`LogTime`, `SignatureAlgoID`, `SignatureBytes`).

Production implementation: `log.HTTPEntryFetcher` calls the operator's `GET /v1/entries/{sequence}` endpoint. Test implementations: `MockFetcher` (in `builder/`) and the in-memory stores backed by test fixtures.

### 27.2 LeafReader — read SMT leaves

```go
type LeafReader interface {
    Get(key [32]byte) (*types.SMTLeaf, error)
}
```

Defined in `core/smt/`. Every verifier takes one; `LeafStore` (the full read-write interface) satisfies it. Production implementation: `smt.HTTPLeafReader` calls the operator's `GET /v1/smt/leaf/{hex_key}` endpoint.

### 27.3 CosignatureQuerier — discover cosignatures

```go
type CosignatureQuerier interface {
    QueryByCosignatureOf(pos types.LogPosition) ([]types.EntryWithMetadata, error)
}
```

Defined in `lifecycle/scope_governance.go`. Used by `CollectApprovals` and similar functions to discover all entries whose `CosignatureOf` points at a specific position. Satisfied by the operator's `OperatorQueryAPI` (defined in `log/operator_api.go`) through structural typing.

The full operator query API includes more queries — `QueryByTargetRoot`, `QueryBySignerDID`, `QueryBySchemaRef`, `ScanFromPosition` — all similarly shaped. Monitoring, indexing, and recovery flows use them.

### 27.4 ContentStore and RetrievalProvider — artifact bytes

Covered in section 8. The write-side (`ContentStore`) and read-side (`RetrievalProvider`) separation is deliberate. The exchange holds no storage credentials; the artifact store does.

### 27.5 The HTTP reference implementations

The SDK ships four HTTP adapters as reference implementations of these contracts:

| Contract | Adapter | Endpoint |
|----------|---------|----------|
| `EntryFetcher` | `log.HTTPEntryFetcher` | `GET /v1/entries/{sequence}` |
| `LeafReader` | `smt.HTTPLeafReader` | `GET /v1/smt/leaf/{hex}` |
| `ContentStore` | `storage.HTTPContentStore` | `POST/GET/DELETE /v1/artifacts/{cid}` |
| `RetrievalProvider` | `storage.HTTPRetrievalProvider` | `GET /v1/artifacts/{cid}/resolve?expiry=N` |

These exist because the SDK treats HTTP as a boundary it doesn't own but commonly uses. If you build a non-HTTP deployment — gRPC, a monorepo with direct database access, a testing harness — you write parallel adapters satisfying the same interfaces. The SDK's verification, lifecycle, and builder code doesn't change.

## 28. Vendor DID mapping with double-blind escrow

One subtle piece that needs its own section because no one will figure it out from the code alone.

### 28.1 The problem

Vendor-specific DIDs — opaque identifiers a consortium or issuer uses to represent customers on the log — are linked to real identities via a mapping held off-log. The mapping is private (public logging would violate structural privacy, Decision 21). But if the issuer disappears, the mapping disappears with them, and vendor DIDs on the log become unrecoverable — credentials stranded.

Protocol-level recovery restores artifact decryption keys and signing keys, but vendor-specific DID mappings are separate data that the issuer holds privately. Without structural support, recovery of mappings requires per-DID issuer cooperation — impossible if the issuer is gone.

### 28.2 The double-blind escrow pattern

```go
func NewMappingEscrow(store storage.ContentStore, cfg MappingEscrowConfig) *MappingEscrow
func (me *MappingEscrow) StoreMapping(record MappingRecord) (*StoredMapping, error)
func (me *MappingEscrow) LookupMapping(identityHash [32]byte,
                                      keyShares []escrow.Share) (*MappingRecord, error)
```

The mapping escrow stores each `MappingRecord` (identity hash → credential reference) encrypted with a fresh AES key, then Shamir-splits the AES key into M-of-N shares distributed to the same escrow nodes that hold the holder's signing key shares. The encrypted blob goes in content-addressed blob storage; the CID goes on the entity profile as an identity-binding entry.

One recovery operation reconstructs both the holder's signing key and the mapping key. Same escrow nodes, same threshold, one M-of-N flow. The new exchange (taking over after the old exchange disappears) decrypts the mapping blob and recovers the vendor-specific DID → real DID binding without issuer cooperation.

`MappingEscrowConfig` defaults to 3-of-5 Shamir. The escrow composes three SDK primitives: `crypto/artifact.EncryptArtifact` (fresh AES key per mapping), `crypto/escrow.SplitGF256` (split the key), `storage.ContentStore` (push the encrypted blob). None of them know about mappings; the mapping escrow assembles them into the double-blind pattern.

The acknowledged caveat: the encrypted mapping blob is publicly addressable by CID. The encryption protects content, but the existence of a mapping blob for every vendor-specific DID is itself metadata. This does not break the privacy model — the CID reveals nothing about content, the DID linkage is inside the encryption, and the adversary model already assumes complete public log access with unlimited compute. The metadata signal is acknowledged; the structural privacy guarantee holds.

---

# Part XI — Cross-Cutting Concerns

These are the rules that don't fit anywhere but apply everywhere. Section 30 is arguably the most important section in the guide — it's what makes Ortholog implementations interoperable.

## 29. Domain / protocol separation

The single most load-bearing principle in the SDK. Stated simply: **the protocol layer carries no domain vocabulary, and domain code never touches the wire format.**

Concretely:
- The Control Header has no "credential type" field, no "record class" field, no "entity category" field. None of those exist in the protocol. Domain type lives in the Domain Payload.
- The builder never reads Domain Payloads. It reads Control Headers, classifies paths, mutates SMT state. An entry could have an empty payload, a 1 MB payload, a plaintext payload, or an encrypted payload — the builder produces the same SMT mutations.
- The verifier's evaluators (`EvaluateOrigin`, `EvaluateAuthority`, etc.) read the Control Header and at most the `Schema_Ref`'s extracted parameters. They don't read credential payloads. Domain verification — "is this license valid for this purpose?" — is a separate layer on top.
- The `SchemaParameters` struct contains only protocol-mechanical parameters (activation delays, cosignature thresholds, override thresholds, encryption scheme). It contains no domain field types. A schema's JSON payload can carry anything beyond the 13 well-known fields; the extractor ignores unknown keys.

Why this matters: it's what lets the same SDK serve a licensing board, a court records system, a credentialing network, a records registry, and a custody tracker with zero forks. It's also what lets a domain evolve its schemas freely — adding fields, changing enums, introducing new record types — without touching protocol code, which requires governance consensus across the entire network of logs.

The reverse side of the coin: **schema changes are domain governance; protocol changes are protocol governance.** A state licensing board can publish schema v2 with new fields whenever they want. An Ortholog protocol change (adding a Control Header field, changing the wire format, revising a path rule) requires every log's witness consortium to agree.

This is why `schema-driven vs protocol-driven evolution` is a governance question, not a design question. Schema-driven evolution is always available; protocol-driven evolution is reserved for changes that can't be expressed as schema changes.

## 30. Determinism requirements

Ortholog's guarantees — cryptographic auditability, fraud proofs, cross-implementation interoperability — rest on determinism. Two correct implementations, given the same inputs, must produce byte-identical outputs. This section lists what *must* be deterministic. If you're implementing an SDK in another language, this is your conformance checklist.

### 30.1 Canonical entry serialization

Byte-for-byte identical output from `envelope.Serialize` across implementations. The rules in section 5.3 are exhaustive. Deviations that break interoperability include:

- Using platform-native byte order instead of big-endian.
- Failing to length-prefix the admission proof body (breaks field isolation).
- Using variable-length integer encoding anywhere.
- Including or excluding trailing padding.
- Varying the presence byte encoding (must be `0` or `1`, never other values).
- Emitting map iteration order-dependent output for `AuthoritySet`.

`ControlHeader.SortedDIDs()` sorts alphabetically before serialization. Any implementation that iterates the `AuthoritySet` in map-native order produces nondeterministic bytes.

### 30.2 Canonical entry hashing

`SHA-256(envelope.Serialize(entry))`. If serialization is deterministic, hashing is. But any off-by-one in serialization — including or excluding a byte — produces a different hash, and therefore a different `CosignatureOf` target, a different Merkle leaf, a different `EvidencePointers` reference. The entry becomes unreachable.

### 30.3 SMT key derivation

`SHA-256(uint16(len(LogDID)) ++ LogDID_bytes ++ uint64_big_endian(Sequence))`. Any variation — UTF-8 BOM in the DID, different length encoding, different endianness on the sequence — produces a different key. An implementation that derives keys differently reaches the wrong leaves.

### 30.4 SMT leaf hashing

Implementation-defined in `smt.hashLeaf`. The current scheme concatenates `Key || OriginTip.LogDID || OriginTip.Sequence(big-endian) || AuthorityTip.LogDID || AuthorityTip.Sequence(big-endian)` and SHA-256s. Any two implementations must produce identical leaf hashes for identical leaves or the SMT root diverges.

### 30.5 Sparse Merkle tree root computation

256-bit depth, default hash `SHA-256(defaultHash[d-1] || defaultHash[d-1])` with leaf-level default `SHA-256(zeros_32)`. Implementations that use a different default hash, a different depth, or a different combine function produce different roots.

### 30.6 Path processing order

Within `ProcessBatch`, entries are processed in the order supplied by the caller. Mutations are recorded in the order they occur. If a batch containing entries `[A, B, C]` produces mutations `[MA, MB, MC]` in one implementation and `[MA, MC, MB]` in another — even if the final tree state is identical — fraud proof verification breaks. The mutation list in derivation commitments is order-sensitive.

### 30.7 Authority chain walking

`verifier.EvaluateAuthority` walks `Prior_Authority` backward in a specific order, applies snapshots and skip pointers in a specific way, and classifies entries by a specific activation-delay test. Different walk orders or different classification logic yield different `ActiveConstraints` lists.

### 30.8 Commutative Δ-window sorting

When commutative OCC accepts concurrent entries, the builder sorts them lexicographically by canonical entry hash before applying to the SMT. An implementation that sorts by position, by receipt time, or by any other criterion produces different mutation orders.

### 30.9 Witness cosign message construction

`types.WitnessCosignMessage(head)` produces a 40-byte structure: `[32-byte root hash][uint64 big-endian tree size]`. Any variation in byte layout breaks cosignature verification across implementations.

### 30.10 Shamir reconstruction

Field-tagged shares (tag 0x01 = GF(256) with Rijndael polynomial). Any implementation using a different field representation reconstructs to the wrong secret — and because AES-256-GCM fails authentication rather than decrypting to garbage, the failure mode is "authentication failed" with no indication that the field was wrong. The tag check catches this at share collection.

### 30.11 ECIES key derivation

Padded ECDH scalars (32 bytes, big-endian), padded coordinate output (32 bytes each for X and Y), SHA-256 over `(padded_X || padded_Y)` produces the AES key. An unpadded implementation diverges on ~1/256 of exchanges.

### 30.12 ECDSA low-S normalization

Entry signatures are low-S normalized (`s ≤ N/2`) with rigorous 32-byte zero-padding on R and S. An implementation emitting high-S signatures or variable-length R/S produces signatures that other verifiers may treat as distinct from the "canonical" form.

### 30.13 What does NOT need to be deterministic

- `Log_Time` — it's operator-assigned metadata, explicitly outside the canonical hash. Different operators backdating or misclocking produce detectable violations.
- Error messages, logging format, metrics labels — internal to each implementation.
- Storage backend implementation — Postgres, RocksDB, in-memory, any other, as long as they implement the `LeafStore` contract atomically.
- Cache TTLs, retry counts, backoff strategies — operational parameters.

If you're porting the SDK, sections 30.1 through 30.12 are the conformance test. An Ortholog implementation that matches those properties interoperates; one that deviates doesn't.

## 31. Error taxonomy and HTTP dispatch

The SDK uses named errors consistently. Callers dispatch on `errors.Is` to map failures to HTTP status codes, audit categories, or recovery actions.

### 31.1 Version policy errors

| Error | HTTP | Meaning |
|-------|------|---------|
| `envelope.ErrUnknownVersion` | 400 Bad Request | Version not in policy table |
| `envelope.ErrVersionDeprecated` | 400 Bad Request | Read-only version, writes blocked |
| `envelope.ErrVersionFrozen` | 410 Gone | Archival-only |
| `envelope.ErrVersionRevoked` | 451 Unavailable | Cryptographically broken |

### 31.2 Envelope errors

| Error | Meaning |
|-------|---------|
| `envelope.ErrCanonicalTooLarge` | Size exceeds 1 MiB |
| `envelope.ErrMalformedPreamble` | Preamble byte layout violation |
| `envelope.ErrMalformedHeader` | Header body parse failure |
| `envelope.ErrMalformedPayload` | Payload length/bytes mismatch |
| `envelope.ErrEmptySignerDID` | Signer DID required |
| `envelope.ErrNonASCIIDID` | Signer DID must be ASCII |
| `envelope.ErrTooManyDelegationPointers` | Cap of 3 exceeded |
| `envelope.ErrTooManyEvidencePointers` | Cap of 32 exceeded on non-snapshot |
| `envelope.ErrAdmissionProofTooLarge` | Admission body exceeds 4096 |

### 31.3 Builder errors

| Error | Meaning |
|-------|---------|
| `builder.ErrTipRegression` | Attempted to move a tip backward |
| `builder.ErrIntermediateNotFound` | `TargetIntermediate` leaf missing |
| `builder.ErrIntermediateForeign` | `TargetIntermediate` on foreign log |
| `builder.ErrChainTooDeep` | Delegation chain exceeds max depth |
| `builder.ErrChainDisconnected` | Path B chain doesn't connect |
| `builder.ErrChainCycle` | Cycle detected in delegation chain |
| `builder.ErrDelegationNotLive` | Delegation revoked |
| `builder.ErrEmptyDelegationChain` | Path B requires pointers |

### 31.4 Admission errors

Every Mode B validation failure has a specific error. The full set is in `crypto/admission/stamp.go`. Operators mapping admission errors to HTTP responses typically return 400 for most (malformed stamp), 429 for `ErrStampEpochOutOfWindow` (try again with fresh epoch), and 403 for `ErrStampTargetLogMismatch` (deliberately wrong target).

### 31.5 Recovery and governance errors

| Error | Meaning |
|-------|---------|
| `lifecycle.ErrRecoveryNotInitiated` | No recovery request on log |
| `lifecycle.ErrInsufficientShares` | Fewer than M valid shares |
| `lifecycle.ErrShareValidationFailed` | Invalid share structure |
| `lifecycle.ErrReconstructionFailed` | Reconstruction math failure |
| `lifecycle.ErrArbitrationRequired` | Custody dispute, escalate to override |
| `lifecycle.ErrInsufficientOverride` | Override lacks schema-declared supermajority |
| `lifecycle.ErrMissingWitnessCosig` | Schema requires independent witness |

### 31.6 Verification errors

Mostly specific per-evaluator. `verifier.ErrLeafNotFound` and `verifier.ErrSchemaNotFound` are the most common. Cross-log verification has its own set: `ErrSourceInclusionFailed`, `ErrSourceHeadInvalid`, `ErrAnchorMismatch`, `ErrLocalInclusionFailed`, `ErrAnchorEntryNotFound`.

### 31.7 Witness errors

`witness.ErrInsufficientWitnesses` (quorum not met), `witness.ErrNoSignatures` (empty), `witness.ErrEmptyWitnessSet` (no keys supplied), `witness.ErrDifferentSizes` (equivocation check hit different sizes — not equivocation), `witness.ErrStaleTreeHead` (staleness check failed).

The rule: if an error is one of these named errors, callers can dispatch on it with `errors.Is`. If a function returns a wrapped, unnamed error, it's a caller programming error (length mismatch, nil interface) or a transport failure that should be propagated without interpretation.

## 32. Thread safety

Not every SDK component is thread-safe. The contract varies by package.

**Safe for concurrent use:**
- `core/smt.Tree` — internal mutex protects mutation tracking; leaf-store implementations provide their own concurrency guarantees (in-memory uses `sync.RWMutex`, HTTP is stateless).
- `core/smt.InMemoryLeafStore`, `InMemoryNodeCache`, `OverlayLeafStore` — thread-safe.
- `storage.InMemoryContentStore` — thread-safe.
- `did.CachingResolver` — thread-safe (internal `sync.RWMutex`).
- `schema.CachingResolver` — thread-safe.
- `witness.TreeHeadClient` — thread-safe.
- `exchange/identity.MappingEscrow` — thread-safe.
- All HTTP adapters — `http.Client` is safe for concurrent use.

**Single-threaded only:**
- `builder.DeltaWindowBuffer` — no internal mutex. Accessed only by the single builder goroutine. Concurrent access from multiple goroutines is a programming error.
- `builder.ProcessBatch` — single-threaded within a single call. Two concurrent `ProcessBatch` calls on the same tree are undefined behavior. The operator serializes batches through a single goroutine that consumes a queue of entries.

**Application-managed:**
- Key material — `artifact.ArtifactKey`, raw private keys, unwrapped `sk_del` values. Callers synchronize access as appropriate for their threat model. The SDK zeros keys after use where it can but doesn't lock them.

The rule: the SDK is thread-safe where it's cheap to be. The builder is single-threaded by design because its correctness depends on ordered mutation and a deterministic delta-window buffer. Running multiple builders against one tree defeats both guarantees.

---

# Appendices

## A. File-by-file index

**`core/envelope/`**
- `api.go` — version constants, wire format limits
- `control_header.go` — the `ControlHeader` struct
- `entry.go` — the `Entry` wrapper
- `serialize.go` — `NewEntry`, `Serialize`, `Deserialize`
- `canonical_hash.go` — hashing convenience
- `version_policy.go` — the four-state version lifecycle
- `signature_wire.go` — signature wire-format wrapping

**`core/smt/`**
- `tree.go` — `Tree`, `LeafStore`, `LeafReader`, `InMemoryLeafStore`
- `keys.go` — `DeriveKey`
- `overlay.go` — `OverlayLeafStore` (write-buffering wrapper)
- `proof_gen.go` — membership and non-membership proofs
- `batch_multiproofs.go` — deduplicated batch proofs
- `verify.go` — proof verification
- `merkle_wrap.go` — append-only Merkle tree interface and stub
- `derivation_commitment.go` — commitment generation and replay
- `http_leaf_reader.go` — HTTP implementation of `LeafReader`

**`types/`** — shared data types, no logic (referenced throughout)

**`builder/`**
- `api.go` — `ProcessBatch`, `BatchResult`, `EntryFetcher`, `SchemaResolver`
- `algorithm.go` — `processEntry` dispatching to Path A/B/C
- `path_compression.go` — compute-then-apply pipeline
- `concurrency.go` — `DeltaWindowBuffer`, OCC verification
- `assemble_path_b.go` — delegation chain assembly
- `entry_builders.go` — 18 typed entry constructors
- `entry_classification.go` — read-only classification
- `occ_retry.go` — exponential backoff wrapper
- `commitments.go` — derivation commitment generation

**`crypto/`**
- `hash.go` — `CanonicalHash`, `HashBytes`
- `signatures/entry_verify.go` — ECDSA entry signing and verification
- `signatures/witness_verify.go` — witness cosignature verification (ECDSA + BLS dispatch)
- `artifact/api.go` — AES-256-GCM encryption, `VerifyAndDecrypt`
- `artifact/pre.go` — Umbral Threshold Proxy Re-Encryption
- `escrow/api.go` — Shamir splitting in GF(256)
- `escrow/share_format.go` — field-tagged share wire format
- `escrow/verify_share.go` — per-share validation
- `escrow/ecies.go` — ECIES share wrapping
- `escrow/blind_routing.go` — enclave attestation interface
- `admission/stamp.go` — Mode B stamp generation and verification
- `admission/adapter.go` — wire-format bridge

**`schema/`**
- `parameters.go` — `SchemaParameterExtractor` interface
- `parameters_json.go` — JSON extractor (13 fields)
- `resolver.go` — caching resolver for builder
- `shard_genesis.go` — shard genesis payload type

**`did/`**
- `resolver.go` — `DIDResolver`, `WebDIDResolver`, `CachingResolver`, adapters
- `creation.go` — key generation, document construction
- `vendor_did.go` — `VendorDIDResolver`

**`lifecycle/`**
- `provision.go` — single-log provisioning
- `scope_governance.go` — three-phase scope amendment and removal
- `recovery.go` — three-phase key recovery, arbitration
- `artifact_access.go` — grant authorization, key storage, verified decryption
- `delegation_key.go` — per-artifact delegation key generation
- `difficulty.go` — high-level stamp wrapper
- `helpers.go` — internal utilities

**`verifier/`**
- `origin_evaluator.go` — O(1) Origin lane read
- `authority_evaluator.go` — authority chain walk, delegation provenance
- `condition_evaluator.go` — activation condition checking
- `contest_override.go` — contest/override detection
- `key_rotation.go` — Tier 2/3 classification
- `delegation_tree.go` — full delegation tree walk
- `schema_succession.go` — schema chain walking, migration evaluation
- `bootstrap.go` — HardcodedGenesis, AnchorLogSync, TrustOnFirstUse
- `cross_log.go` — cross-log compound proof verification
- `fraud_proofs.go` — derivation commitment replay
- `shard_chain_verifier.go` — shard genesis chain walking

**`witness/`**
- `verify.go` — K-of-N cosignature verification
- `rotation.go` — rotation and chain walking
- `equivocation.go` — equivocation detection
- `staleness.go` — freshness bounds
- `tree_head_client.go` — tree head fetching and caching

**`storage/`**
- `cid.go` — CID type, computation, parsing
- `content_store.go` — `ContentStore`, `RetrievalProvider` interfaces and in-memory implementations
- `http_content_store.go` — HTTP implementation
- `http_retrieval_provider.go` — HTTP retrieval

**`log/`**
- `operator_api.go` — `OperatorQueryAPI` interface
- `http_entry_fetcher.go` — HTTP `EntryFetcher`

**`exchange/identity/`**
- `mapping_escrow.go` — vendor DID mapping with double-blind escrow

**`monitoring/`**
- `types.go` — shared alert vocabulary (see appendix D)

## C. Glossary

**Anchor entry** — a commentary entry on log A that commits to log B's cosigned tree head. Enables cross-log verification.

**Authority snapshot** — a Path C entry whose `Evidence_Pointers` reference every currently active enforcement entry on the target. Compacts the authority chain from O(historical) to O(active).

**Authority_Tip** — one of two SMT leaf lanes. Tracks enforcement state. Advanced by Path C enforcement entries.

**Capsule** — the Umbral PRE encryption artifact containing the ephemeral key and verification point. Lives in Domain Payload; public.

**CFrag** — ciphertext fragment. Produced by a re-encryption node running one kfrag against a capsule. Carries a DLEQ proof.

**Commutative OCC** — optimistic concurrency control mode where operations within a Δ-window are all accepted and sorted by hash. Schema-declared.

**Control Header** — the protocol-level metadata block of an entry. Read by the builder. Locked to protocol governance.

**Delta-window buffer** — builder working memory holding recent `Authority_Tip` values per leaf. Used for commutative OCC.

**Derivation commitment** — an entry published by a state-map operator describing a batch's mutations. Replayable for fraud proofs.

**Domain Payload** — schema-defined content of an entry. Opaque to the builder. Free to evolve via schema versioning.

**ECIES** — Elliptic Curve Integrated Encryption Scheme. Used for encrypting escrow shares for specific recipients.

**Entity profile** — root entity entry representing a DID. Holds key rotation pre-commitments and key generation mode.

**Enforcement entry** — Path C entry that advances `Authority_Tip`. Represents a constraint on the target entity.

**Equivocation** — two cosigned tree heads at the same size with different roots. Proven cryptographically.

**Evidence pointers** — Control Header field carrying references to supporting entries. Capped at 32 except on authority snapshots.

**Genesis** — the compiled-in witness set used as the root of trust for `HardcodedGenesis` bootstrap.

**KFrag** — re-encryption key fragment. Shamir-split from a master re-encryption key, distributed to re-encryption nodes.

**LogPosition** — `(LogDID, Sequence)` pair. The protocol's universal pointer.

**Log_Time** — operator-assigned admission timestamp. Outside the canonical hash.

**Origin_Tip** — one of two SMT leaf lanes. Tracks content state. Advanced by Path A, B, or scope-amendment entries.

**Path A/B/C/D** — the protocol's five state-affecting routes (Path D is the bit bucket).

**Path compression** — using `TargetIntermediate` to update two leaves in one entry.

**Prior_Authority** — Control Header field carrying the `Authority_Tip` the writer observed. Used for OCC.

**Protocol governance** — unanimous agreement across witness consortiums. Required for Control Header changes.

**Scope entity** — root entity with an `AuthoritySet` that governs Path C entries.

**Snapshot** — see "authority snapshot."

**Tier 2 rotation** — pre-committed + matured key rotation. Immediate effect, no contest.

**Tier 3 rotation** — new key without matching pre-commitment. Activation delay, identity witness, contest window.

**Umbral PRE** — Umbral Threshold Proxy Re-Encryption. Grants decryption capability without revealing plaintext or master key.

**Witness cosignature** — K-of-N signatures over a tree head. Published by the witness consortium.

## D. Known limitations

Limitations that affect how you build on the SDK. Most are acknowledged in the protocol specification; they're repeated here because they're load-bearing for deployment planning.

**Data availability is layered, not centralized.** The log operator bears primary responsibility (certification requires replicated storage with durability SLAs). Exchanges retain copies of submitted entries. Monitoring services maintain independent copies. Witnesses attest to tree head integrity, not data storage. Mutual anchoring proves state existed at anchored points but does not recover individual entry data. In catastrophic log operator storage loss, entry data must be reconstructed from exchange and monitoring service copies. This is identical to Certificate Transparency's model.

**Vendor-specific DID mapping recovery requires escrow.** Without the double-blind mapping escrow pattern (section 28), recovery of vendor-specific DID mappings requires issuer cooperation on a per-DID basis. Legacy or non-compliant exchanges that did not escrow their mappings cannot have those mappings reconstructed if the exchange disappears. The SDK provides the escrow primitives; it's a domain choice to use them.

**No dealer-free distributed key generation.** Exchange-managed key generation is dealer-based (the exchange generates in its HSM). Client-side blind generation eliminates the exchange-as-dealer, but the client's secure enclave is still a single dealer. Dealer-free protocols (Pedersen DKG) are a future enhancement not shipped in this SDK.

**Commutative operations have no automatic verification.** A schema declaring `Commutative_Operations` is asserting order-independence for all Path C entries under that schema. The builder cannot check this; schema certification requires auditor review. An incorrectly-declared commutative schema produces silent semantic corruption.

**BLS support requires external injection.** The SDK ships no BLS12-381 implementation. Deployments needing BLS witness cosignatures inject a verifier; deployments using ECDSA only pass nil and never touch BLS. The scheme tag on cosigned tree heads makes the choice per-rotation, not global — so a deployment can migrate when BLS is available on its target.

**The monitoring package is vocabulary, not engine.** `monitoring.Alert`, `monitoring.Severity`, `monitoring.Destination` are shared types. There's no monitoring engine, no subscription mechanism, no alert router in the SDK. Consumers build engines against the vocabulary. This keeps the SDK free of operational opinions (Prometheus vs. OpenTelemetry vs. PagerDuty vs. custom) that would bind it to specific deployment choices.

**The builder is local-only (Decision 47).** Cross-log authority requires local representation via a mirror delegation entry or local scope membership. The SDK does not fetch from foreign logs during state resolution. Cross-log integrity is the verifier's responsibility via compound proofs. This bounds builder computation at the cost of requiring extra entries for cross-log scenarios.

**Log_Time is trusted at the operator's discretion.** It's outside the canonical hash, so it's not cryptographically bound to the entry. Operator backdating or forward-dating is detectable through cross-log timestamp comparison and monitoring, but not structurally prevented. Certification violations are the enforcement mechanism, not cryptographic impossibility.

**No deletion of log entries.** Once admitted, entries are permanent. Cryptographic erasure via key destruction applies to artifact content in CAS, not to Control Headers on the log. GDPR-style deletion requires pre-emptive encryption and key escrow — the protocol supports this pattern but does not enforce it.