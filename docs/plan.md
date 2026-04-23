# Phase C — v7.75 Complete Execution Plan

Nine groups. Dependencies flow forward: Group N assumes 1..N-1 are green. Every group has a single named closure proof. v7.75 is scoped to ship as a complete SDK release; there is no Phase D.

The plan assumes `adr.md` (ADR-005) is locked and authoritative. Every DST string, every wire-format constant, every mutation-audit discipline rule referenced below is specified there. Where this plan references a file or function, it is because its contents have been read in this thread.

---

## Group 1 — Canonicalization Foundation

**Packages:** `crypto/hash.go`, `storage/cid.go` (read-only reference), `internal/testkeys/` (support only, no change)

**Purpose:** Ship the single byte-formatting primitive that every downstream cryptographic identifier will route through. Nothing else in Phase C compiles correctly until this lands — every SplitID migration, PRE grant commitment derivation, domain-app DST construction, and the universal length-prefix rule all depend on one helper.

**Subgroup 1.1 — `LengthPrefixed` primitive.** Add `LengthPrefixed(dst string, fields ...[]byte) [32]byte` to `crypto/hash.go`. Implementation writes, in order: 2-byte big-endian length of DST, DST bytes, then for each field: 2-byte big-endian length, field bytes. Final SHA-256 digest. Zero interpretation of field contents — raw bytes in, raw bytes hashed. Godoc explicitly states three things: the TupleHash discipline (length-prefix everything, no exceptions), the BLS12-381 RFC 9380 hash-to-curve carveout (DSTs in that path follow IETF specification and do NOT route through this helper; the cosignature domain tag and PoP domain tag in `crypto/signatures/bls_verifier.go` are the named exceptions), and the caller-normalizes contract (NFC normalization happens at edges, never inside this function). The 2-byte length caps field size at 65535 bytes; exceeding it panics because any legitimate cryptographic identifier fits comfortably under this bound and a >65KB field is a caller bug.

**Subgroup 1.2 — CID authoritative byte-form discipline.** No code change to `storage/cid.go`. Create `storage/cid_test.go` (no test file currently exists inside the `storage/` package itself) and add a regression test asserting that `artifactCID.Bytes()` is the authoritative wire form — the 1-byte algorithm tag plus the variable-length digest — and that any SplitID derivation which consumes a CID must use `Bytes()`, never `Digest` alone. The test is a guard against a future engineer shortcutting to `.Digest` and accidentally producing cross-algorithm collisions. Evidence that this matters: the `RegisterAlgorithm` function in `storage/cid.go` is public, other algorithms can legitimately register, and `Bytes()` returns `algorithm_byte || digest` which is inherently variable-length. ADR-005 §2 mandates `CID.Bytes()` specifically for the PRE Grant SplitID construction, locking this contract at the cryptographic layer.

**Closure proof.** `TestLengthPrefixed_BoundaryShift` pins that `LengthPrefixed("DA", []byte("lice"))` ≠ `LengthPrefixed("D", []byte("Alice"))` — the boundary-shifting attack the universal rule exists to prevent. Four golden vectors with pinned 32-byte digests cover: empty DST + empty field, empty DST + standard field, standard DST + empty field, standard PRE case with realistic DIDs and a SHA-256 CID. `TestCID_BytesIncludesAlgorithmTag` (in the newly created `storage/cid_test.go`) constructs a CID and verifies `Bytes()[0]` equals the algorithm byte; a second assertion verifies two CIDs with identical 32-byte digests under different hypothetical algorithm tags produce distinct `Bytes()` outputs. `TestLengthPrefixed_BLSCarveoutDocumented` is a runtime `go/ast` or regex regression test that parses the `crypto/hash.go` source and verifies the godoc contains the RFC 9380 carveout language along with the named function exceptions from `bls_verifier.go` — a regression guard against the doc being silently stripped or drifting out of sync with the actual BLS code.

**Verification for Group 1.** `go test ./crypto/...` and `go test ./storage/...` green. Four golden vectors locked in testdata. `storage/cid_test.go` created and passing. One-line note added to `docs/crypto.md` cross-referencing the rule for downstream readers. `grep -rn 'sha256.Sum256' crypto/ core/` reviewed to identify any site that hashes variable-length fields without length-prefixing — if found, either migrated in later groups or documented as an intentional exception (e.g., RFC 6962 leaf hash in `core/envelope/` which is protocol-mandated).

---

## Group 2 — SplitID Migration + Schema Parameters v7.5 Verification

**Packages:** `crypto/artifact/`, `crypto/escrow/vss_v2.go`, `schema/parameters_json.go`, `types/schema_parameters.go`

**Purpose:** Apply the universal length-prefix rule to both SplitID derivations — one new (PRE), one migrated (escrow) — and verify the v7.5 schema-parameters restructure is locked with an exhaustive round-trip regression gate. The legacy `ComputeEscrowSplitID` construction in `vss_v2.go` uses raw concatenation of `(DST, BE_uint16(len(DID)), DID, nonce)`. That construction breaks the universal rule (the DST and nonce are not length-prefixed). The migration is a hard break — every SplitID produced by `ComputeEscrowSplitID` changes — and because Phase C is pre-production, this is the correct time to absorb it. ADR-005 §2 formalizes the canonical construction for both SplitIDs.

**Subgroup 2.1 — `ComputePREGrantSplitID`.** New function in a new file `crypto/artifact/split_id.go`. Signature: `ComputePREGrantSplitID(grantorDID, recipientDID string, artifactCID storage.CID) [32]byte`. Body calls `crypto/hash.LengthPrefixed` with `DST = "ORTHOLOG-V7.75-PRE-GRANT-SPLIT-ID-v1"` (versioned per ADR-005 §2 to allow future construction migrations without breaking the rule) and three fields: `[]byte(grantorDID)`, `[]byte(recipientDID)`, `artifactCID.Bytes()`. Godoc locks the caller-normalizes contract explicitly — DIDs are expected to be NFC-normalized at the edge. Godoc also documents that `artifactCID.Bytes()` is used rather than `artifactCID.Digest` for cross-algorithm collision resistance, and references ADR-005 §2 as the locking specification. Locked golden fixture at `crypto/artifact/testdata/pre_grant_split_id_vector.json` with a pinned `(grantorDID, recipientDID, artifactCID)` triple and the pinned 32-byte output.

**Subgroup 2.2 — Migrate `ComputeEscrowSplitID`.** Replace the existing construction in `crypto/escrow/vss_v2.go`. The `EscrowSplitDST` constant gets deleted. The `ComputeEscrowSplitID` function body becomes a single call through `LengthPrefixed("ORTHOLOG-V7.75-ESCROW-SPLIT", []byte(dealerDID), nonce[:])`. The nonce is length-prefixed even though it's a fixed `[32]byte` — applying the rule uniformly beats case-by-case reasoning about "truly fixed" fields, per ADR-005 §2. The marginal byte cost is trivial. New golden fixture at `crypto/escrow/testdata/split_id_vector.json`; old fixture (if any) deleted. `TestSplitV2_GoldenVector` regenerated with new expected bytes.

Note on scope: `exchange/identity/mapping_escrow.go` uses the V1 `escrow.Split` protocol, which generates its `SplitID` from random bytes via `crypto/rand` — it does NOT call `ComputeEscrowSplitID`. There are no pinned `SplitID` bytes derived from the migrated function in `tests/mapping_escrow_test.go`, `tests/phase6_part_b_test.go`, `tests/phase6_part_c_test.go`, or `tests/integration/pre_lifecycle_integration_test.go`. An earlier draft of this plan proposed a "downstream bind-check regeneration" subgroup for these files; re-reading the source refuted that scope. Those integration tests are unaffected by the migration and need no fixture regeneration.

**Subgroup 2.3 — Schema parameters v7.5 lock.** Evidence from `schema/parameters_json.go` and `builder/entry_builders.go`: the v7.5 restructure already landed. `BuildSchemaEntry` takes `types.SchemaParameters` and marshals via `schema.MarshalParameters`. `parameters_json_roundtrip_test.go` exists as the permanent regression gate. This subgroup closes the work by: (1) grep-auditing for any remaining hand-rolled schema JSON — `grep -rn 'cosignature_threshold' --include='*.go'` catching any raw `json.Marshal(map[string]any{...})` pattern; (2) verifying round-trip coverage is exhaustive across all 13 well-known fields, all 4 enum types, the `-1` sentinel for `CredentialValidityPeriod` nil, and the `CommutativeOperations` empty-vs-populated distinction; (3) adding `TestMarshalParameters_RejectsUnknownEnum` for each of the four enums.

**Closure proof.** `TestComputePREGrantSplitID_GoldenVector` passes. `TestComputePREGrantSplitID_NFCEdgeCase` passes (pins that NFC and NFD forms of the same visual string produce different SplitIDs). `TestComputePREGrantSplitID_CIDAlgorithmBinding` passes (pins that the same 32-byte digest under different algorithm tags produces different SplitIDs). `TestComputeEscrowSplitID_GoldenVector` passes with the new construction. `TestSplitV2_GoldenVector` regenerated and passes. `grep -rn 'ORTHOLOG-V7.75-ESCROW-SPLIT' --include='*.go'` returns hits only inside `vss_v2.go` and `crypto/hash.go` godoc. `grep -rn 'EscrowSplitDST' --include='*.go'` returns zero hits. `grep -rn 'json.Marshal(map\[string\]any{.*cosignature_threshold' --include='*.go'` returns zero hits. Round-trip test covers all 13 fields × enum permutations. Full `go test ./...` green.

**Verification for Group 2.** Both SplitID derivations route through `LengthPrefixed`. Two golden vectors locked. Zero references to the legacy raw-concat construction. Schema parameters v7.5 round-trip is exhaustive.

---

## Group 3 — Complete Commitment Surface + Lifecycle Atomic Emission

**Packages:** `crypto/artifact/`, `crypto/escrow/`, `builder/entry_builders.go`, `schema/`, `lifecycle/artifact_access.go`, `lifecycle/provision.go`, `exchange/identity/mapping_escrow.go`, `core/vss/` (read-only dependency)

**Purpose:** Ship the complete commitment-entry surface within the SDK — structs, serializers, verifiers, builders, schema registration, and atomic lifecycle emission for both escrow and PRE subsystems. ADR-005 §4 locks this surface as SDK-complete; there is no downstream phase that finishes it. A caller invoking `grantUmbralPRE`, `ProvisionSingleLog`, or `StoreMapping` gets the commitment entry structurally attached to the shares/KFrags in the same atomic operation; they cannot emit one without the other.

Evidence from `lifecycle/artifact_access.go`: v7.75 Phase C is partially in-flight here — `GrantArtifactAccessResult.Commitments` exists, `grantUmbralPRE` threads commitments through `PRE_GenerateKFrags` and into every `PRE_ReEncrypt` call, `VerifyAndDecryptArtifact` gates on `ErrMissingCommitments` when the encryption scheme is PRE. What's missing is the wire-format side, the escrow parity, the builders, the schema registration, the atomic emission wiring, and the lookup primitives.

**Subgroup 3.1 — KFrag plaintext wire.** New `SerializeKFrag(kf KFrag) ([]byte, error)` and `DeserializeKFrag(data []byte) (*KFrag, error)` in `crypto/artifact/pre.go`. 196 bytes total per ADR-005 §5: 99 active material + 97 reserved zero-padding. The active layout is ID (1 byte) + RKShare (32 bytes, big-endian via `padBigInt`) + VK compressed (33 bytes via `compressedPoint`) + BK (33 bytes, already compressed in the struct). Shares the existing `compressedPoint`, `decompressPoint`, `padBigInt` helpers with CFrag serialization — this is load-bearing because any drift between KFrag and CFrag point encoding is a cross-layer bug waiting to happen. Extracts the reserved-zone check into a shared unexported helper `assertReservedZoneZero(data []byte, offset, length int) error` that both CFrag and KFrag deserialization call. New sentinel `ErrKFragReservedBytesNonZero`. New `muEnableKFragReservedCheck` compile-time constant paralleling the existing `muEnable*` discipline in `pre.go`, with full block-comment warning and "Tests that MUST fail when this is false" enumeration.

**Subgroup 3.2 — `PREGrantCommitment` struct and surface.** New type in a new file `crypto/artifact/pre_grant_commitment.go`:

```go
type PREGrantCommitment struct {
    SplitID       [32]byte
    M             byte
    N             byte
    CommitmentSet [][33]byte
}
```

`SerializePREGrantCommitment(c PREGrantCommitment) ([]byte, error)` produces `SplitID || M || N || CommitmentSet[0] || ... || CommitmentSet[M-1]`. Total size is `34 + 33*M` bytes, maximum 8,449 bytes at M=255. `DeserializePREGrantCommitment(data []byte) (*PREGrantCommitment, error)` validates size equals the expected M-derived length, threshold bounds `2 <= M <= N <= 255`, and every point on-curve. The in-memory `vss.Commitments` type uses 65-byte uncompressed points (evidence from `core/vss/pedersen.go` — `elliptic.Marshal` is called with no compression); the `PREGrantCommitment` serializer converts to 33-byte compressed at the wire boundary. Godoc explicitly documents this RAM-vs-wire asymmetry. Constructor helper `NewPREGrantCommitmentFromVSS(splitID [32]byte, M, N int, commitments vss.Commitments) (*PREGrantCommitment, error)` handles the uncompressed-to-compressed conversion at the boundary.

`VerifyPREGrantCommitment(c *PREGrantCommitment, grantorDID, recipientDID string, artifactCID storage.CID) error` verifies exactly four properties and nothing else per ADR-005 §4: (1) every point in `CommitmentSet` is a valid on-curve secp256k1 point, (2) `len(CommitmentSet) == M`, (3) threshold bounds `2 <= M <= N <= 255`, (4) `SplitID == ComputePREGrantSplitID(grantorDID, recipientDID, artifactCID)`. Four new mutation switches — `muEnableCommitmentOnCurveGate`, `muEnableCommitmentSetLengthCheck`, `muEnableThresholdBoundsCheck`, `muEnableSplitIDRecomputation` — each gating its respective check. Explicitly does NOT verify envelope signatures, log membership, or recipient authorization; those are lifecycle-layer concerns handled in Subgroup 3.5.

**Subgroup 3.3 — `EscrowSplitCommitment` parity surface.** New type in a new file `crypto/escrow/split_commitment.go`:

```go
type EscrowSplitCommitment struct {
    SplitID       [32]byte
    M             byte
    N             byte
    DealerDID     string
    CommitmentSet [][33]byte
}
```

`SerializeEscrowSplitCommitment` produces `SplitID || M || N || BE_uint16(len(DealerDID)) || DealerDID || CommitmentSet[0] || ... || CommitmentSet[M-1]`. The DealerDID is length-prefixed in the wire form because it is variable-length; this is uniform with the universal length-prefix rule even though the commitment is not itself a hashed input.

`VerifyEscrowSplitCommitment(c *EscrowSplitCommitment, nonce [32]byte) error` verifies the four parallel properties: on-curve, commitment set length, threshold bounds, and `SplitID == ComputeEscrowSplitID(c.DealerDID, nonce)`. Four new mutation switches parallel the PRE side: `muEnableEscrowCommitmentOnCurveGate`, `muEnableEscrowCommitmentSetLengthCheck`, `muEnableEscrowThresholdBoundsCheck`, `muEnableEscrowSplitIDRecomputation`. Constructor helper `NewEscrowSplitCommitmentFromVSS` handles uncompressed-to-compressed conversion.

Parity is the key property here: any audit, governance, or cross-implementation port that works against the PRE commitment surface works identically against the escrow commitment surface with variable names swapped. No subsystem-specific asymmetries.

**Subgroup 3.4 — Builders and schema registration.** New functions in `builder/entry_builders.go`:

- `BuildPREGrantCommitmentEntry(commitment PREGrantCommitment, signerKey, destination) (*envelope.Entry, error)` — produces a signed Path A commentary entry (TargetRoot null, AuthorityPath null) carrying the serialized commitment as its DomainPayload under schema `pre-grant-commitment-v1`. Calls `validateCommon(signerDID, destination)` like every other builder.

- `BuildEscrowSplitCommitmentEntry(commitment EscrowSplitCommitment, signerKey, destination) (*envelope.Entry, error)` — parallel structure under schema `escrow-split-commitment-v1`.

New schema declaration files `schema/pre_grant_commitment_v1.go` and `schema/escrow_split_commitment_v1.go`. Both declare the schema ID, the payload validator (re-derives the SplitID from the commitment's embedded fields and verifies it matches; validates threshold bounds and on-curve points at admission), and hook into the admission dispatcher. Extend `parameters_json_roundtrip_test.go` coverage so the two new schemas round-trip cleanly.

**Subgroup 3.5 — Atomic lifecycle emission.** The atomicity invariant is structural in the lifecycle API per ADR-005 §4: callers cannot emit a grant or split without the commitment entry. Implementation:

- `grantUmbralPRE` in `lifecycle/artifact_access.go`: produce the `PREGrantCommitment` from the VSS output inline, build the commitment entry via `BuildPREGrantCommitmentEntry`, and return it as a required field of `GrantArtifactAccessResult.CommitmentEntry` alongside the existing `Commitments`, `KFrags`, and other fields. The caller-facing contract is "the batch you submit to the log must include CommitmentEntry"; if it does not, admission rejects the grant. `GrantArtifactAccessResult` cannot be constructed without the `CommitmentEntry` field populated.

- `ProvisionSingleLog` and `StoreMapping` in `lifecycle/provision.go` and `exchange/identity/mapping_escrow.go` respectively: parallel structure for the escrow side. Each produces the `EscrowSplitCommitment`, builds the commitment entry, and returns it structurally coupled to the shares.

- Receive-side enforcement: escrow nodes and PRE recipients receiving shares or KFrags MUST verify the corresponding commitment entry exists on-log (via the lookup primitives in Subgroup 3.6) before accepting the material. Material without a matching commitment entry is rejected as structurally malformed. This enforcement is documented in the receive-path godoc but is an operator responsibility at the deployment layer, not SDK-enforced (the SDK cannot force an operator's receive loop to call the verifier).

New mutation switch `muEnableCommitmentEmissionAtomic` in the lifecycle layer gates an internal assertion that the commitment entry is non-nil when the shares are non-nil. Flipping it false allows the lifecycle function to return shares without a commitment; the binding test confirms downstream admission rejects the grant when this happens.

**Subgroup 3.6 — Lookup primitives.** New exported helpers:

- `FetchPREGrantCommitment(fetcher types.EntryFetcher, grantorDID, recipientDID string, artifactCID storage.CID) (*PREGrantCommitment, error)` in `crypto/artifact/pre_grant_commitment.go`. Derives the SplitID via `ComputePREGrantSplitID`, queries the log for the `pre-grant-commitment-v1` entry with matching SplitID, deserializes, returns. Handles the equivocation case per ADR-005 §3: if the fetcher returns multiple entries with the same SplitID, the function returns `ErrCommitmentEquivocation` carrying both entries for the caller to report.

- `FetchEscrowSplitCommitment(fetcher types.EntryFetcher, splitID [32]byte) (*EscrowSplitCommitment, error)` in `crypto/escrow/split_commitment.go`. Parallel structure. The escrow SplitID is not deterministic from public context (the nonce is private to the dealer), so the caller supplies the SplitID directly — typically from the share envelope's SplitID field.

These primitives are consumed by `VerifyAndDecryptArtifact` (PRE side) and `escrow.Reconstruct` (escrow side) before any cryptographic verification that needs the commitment set.

**Subgroup 3.7 — End-to-end integration test.** Simulates the full grant → publish → verify cycle. Grantor calls `GrantArtifactAccess` with a PRE schema. The returned `CommitmentEntry` is submitted to a mock log alongside the grant. Recipient calls `FetchPREGrantCommitment` with public grant context, confirms the entry is retrievable. Recipient calls `VerifyPREGrantCommitment` against the retrieved entry, confirms it verifies. Recipient calls `VerifyAndDecryptArtifact` with the commitments, CFrags, capsule, and ciphertext; decryption succeeds. Negative variants: tamper with any commitment point after serialization (verify fails); tamper with `SplitID` (verify fails via `muEnableSplitIDRecomputation`); publish a second commitment entry with the same SplitID (`FetchPREGrantCommitment` returns `ErrCommitmentEquivocation`). Parallel integration test for the escrow side.

**Closure proof.** `TestKFrag_SerializeWireFormat_196Bytes`, `TestKFrag_RoundTripSerialization`, `TestKFrag_ReservedBytesNonZeroRejected_EachPosition` (97-offset sweep), `TestKFrag_LayoutOffsets`, `TestKFrag_GoldenVector` with pinned 196-byte output. `TestPREGrantCommitment_RoundTrip`, `TestPREGrantCommitment_SizeCap_M255` validating the 8,449-byte maximum, `TestPREGrantCommitment_ThresholdBoundsRejected` covering M<2, M>N, N>255. `TestPREGrantCommitment_GoldenVector` with pinned serialization. Parallel escrow commitment tests. One binding test per mutation switch (KFrag reserved + four PRE commitment gates + four escrow commitment gates + atomic emission gate = ten new switches). `TestBuildPREGrantCommitmentEntry` and `TestBuildEscrowSplitCommitmentEntry` cover the builders. Schema round-trip tests cover both new schemas. `TestPREGrantLifecycle_Integration` and `TestEscrowSplitLifecycle_Integration` pass end-to-end. `TestPREGrantLifecycle_TamperedCommitments_Rejected`, `TestPREGrantLifecycle_EquivocationDetected`, and parallel escrow variants pass. `TestGrantArtifactAccess_AtomicCommitmentEmission` confirms the `CommitmentEntry` field is populated and non-nil on every success path.

**Verification for Group 3.** KFrag and both commitment types have golden vectors pinned. Ten new mutation switches all have binding tests that genuinely fail when flipped. Integration tests cover the full cryptographic cycle for both subsystems. Atomic emission is structurally enforced at the lifecycle API. Lookup primitives handle the equivocation case. `grep 'muEnable[A-Za-z]\+\s*=\s*false' --include='*.go'` returns zero.

---

## Group 4 — Mutation Audit Infrastructure

**Packages:** `cmd/audit-v775/`, `scripts/verify-phase-c-decomm.sh` (extension), `docs/audit/`, `Makefile`

**Purpose:** Make the mutation-audit discipline machine-verifiable at the scale Groups 5, 6, and 8 demand. By end of Group 3 there are roughly seventeen `muEnable*` constants in the SDK (six pre-existing in `pre.go`, four in `pre_grant_commitment.go`, four in `split_commitment.go`, one KFrag reserved, one atomic emission, plus the pre-existing transcript DST mutation). Groups 5, 6, and 8 will add roughly thirty-five more. Past the ~15 switch threshold, hand-audit becomes untrustworthy — the auditor starts skipping "obvious" cases, the dated log entries drift, and the discipline's whole value evaporates. This group builds the tooling that keeps every switch honest. ADR-005 §6 locks the discipline as permanent; this group ships the enforcement.

**Subgroup 4.1 — Gate-test registry format.** Lock a YAML schema for per-file audit registries, colocated with the source file they describe. Schema:

```yaml
file: crypto/artifact/pre.go
gates:
  muEnablePedersenCheck:
    description: "Pedersen polynomial-consistency binding"
    tests:
      - TestPRE_SubstitutedRKShare_Rejected
      - TestPRE_CoalitionAttack_Rejected
      - TestPRE_WrongCommitments_Rejected
```

Populate four reference registries at the end of Group 4: `crypto/artifact/pre.mutation-audit.yaml` with the six pre-existing switches, `crypto/artifact/pre_grant_commitment.mutation-audit.yaml` with the four new PRE commitment switches from Group 3, `crypto/escrow/split_commitment.mutation-audit.yaml` with the four new escrow commitment switches from Group 3, and `core/vss/transcript.mutation-audit.yaml` documenting the DST-flip mutation (which is a string mutation, not a muEnable toggle — the schema allows a `string_mutation` gate type for this case). The `TestPRE_MutationDiscipline` documentation test in `pre_test.go` gets updated to reference the runner rather than listing steps in a `t.Log` block.

**Subgroup 4.2 — Mutation audit runner.** Build a new Go program under `cmd/audit-v775/` — preference over extending the bash script because parsing YAML and orchestrating `go test` from bash gets ugly fast. The runner: reads a registry, for each gate flips the constant to `false` via textual replacement (`go/ast` rewrite preferred; `sed` is error-prone against multi-line `const (...)` blocks), runs the listed tests with `go test -run '^TestName$'`, asserts non-zero exit, restores the constant, runs the same tests again, asserts zero exit. Records each gate's pass/fail with ISO8601 timestamp in `docs/audit/mutation-audit-log.md`. The log is append-only and committed to the repo.

**Subgroup 4.3 — CI guard extension.** The existing `scripts/verify-phase-c-decomm.sh` scans for `muEnable.*=\s*false`. Extend it with a second pass that reads every `*.mutation-audit.yaml` registry and verifies every declared gate constant actually exists in the named source file (via `go/ast` or `grep` with anchoring), and every declared test function actually exists in the test files. This catches drift in both directions: a registry claiming a gate that was deleted, or a gate being added without a registry entry. Wire into `Makefile` as a `make audit-v775` target and into pre-commit as a hook.

**Closure proof.** Four reference registries validated by `cmd/audit-v775 --validate-registries`. End-to-end runner executes on Tier 1 switches (six from pre.go, four from pre_grant_commitment.go, four from split_commitment.go, one transcript DST = fifteen gates total, plus the KFrag reserved and atomic emission switches = seventeen) and produces seventeen dated pass entries in the audit log. Deliberately-staged `muEnableCommitmentsGate = false` in a diff causes `make audit-v775` to exit non-zero. Deliberately-staged deletion of a registered constant causes the validator to exit non-zero with a clear drift message.

**Verification for Group 4.** Tooling exists, passes end-to-end on Tier 1, and catches the three failure modes the discipline is supposed to prevent (gate flipped off, gate deleted without registry update, registry entry without matching source constant). `make audit-v775` is a single command anyone can run.

---

## Group 5 — Tier 1 Polish + Tier 2 Primitive Audit

**Packages:** `core/vss/`, `crypto/escrow/`, `crypto/signatures/`, `core/envelope/`, `core/smt/`, `crypto/artifact/` (Tier 1 items)

**Purpose:** Close every primitive-level security gate in the SDK under the mutation-audit discipline. This is the bulk of the audit surface. The approach is file-by-file through the Group 4 tooling: read-pass to inventory gates, factor inline gates into named functions, add `muEnable*` constants with full block-comment warnings, write or verify binding tests, create the `.mutation-audit.yaml` registry, run the mutation audit, commit with dated audit-log entry.

**Subgroup 5.1 — Tier 1 closure items.** Four small items that belong in Phase C's Tier 1 but weren't yet done. First: M4 transcript DST mutation. Flip one byte of `TranscriptDST` in `core/vss/transcript.go` (e.g., change `ORTHOLOG-V7.75-DLEQ-CHALLENGE-v1` to `ORTHOLOG-V7.75-DLEQ-CHALLENGE-v2`), run the full PRE and VSS test suites, confirm `TestPRE_DLEQTranscript_Golden` and `transcript_vector.json`-bound tests fail, restore, confirm green. Log the result in the audit appendix. Second: convert the two `t.Skip` paths in `TestPRE_DLEQTranscript_Golden` (evidence from `pre_test.go`: `t.Skipf("fixture not readable (%v); Phase A test covers the primary assertion", err)` and `t.Skip("fixture lacks expected.challenge_hex; Phase A primary coverage suffices")`) to `t.Fatalf` — skipped tests pass, and if the fixture is ever deleted the M4 mutation will silently not fire. Third: add `TestPRE_DecryptFrags_RejectsOffCurveOwnerKey_Isolated` that builds a legitimately-verifying CFrag set, then tampers with `pkOwner` to an off-curve point, and confirms rejection at the `gateOwnerKeyValid` gate. The existing `TestPRE_DecryptFrags_RejectsMalformedCFrags` docstring explicitly admits this isolated coverage is missing; this closes it. Fourth: update `TestPRE_MutationDiscipline` to reference the Group 4 runner rather than hand-enumerating steps.

**Subgroup 5.2 — VSS and escrow primitives.** Four files. `core/vss/pedersen.go`: audit `VerifyPoints` (the point-level Pedersen check that `pre.go`'s `checkPedersen` delegates to) for gate factorization. Evidence from the shared contents: the function already has reasonable structure with explicit index bounds, non-empty commitments check, on-curve validation, nil-point check. Add `muEnablePedersenIndexBounds`, `muEnablePedersenOnCurveCheck` constants and binding tests. `core/vss/h_generator.go`: audit `HGenerator` and the `deriveHGenerator`/`liftX`/`candidateX` helpers. The seed-byte-flip mutation is the key audit — any single-byte change to `HGeneratorSeed` produces a different H and invalidates every commitment. Binding test: pin the fixture `testdata/h_generator.json` values, flip one seed byte, confirm fixture test fails. Add `muEnableHGeneratorLiftX` gating the ModSqrt/IsOnCurve branch. `crypto/escrow/verify_share.go`: the V1/V2 dispatch is already clean (evidence from shared contents — `validateShareFormatV1` and `validateShareFormatV2` are sibling functions). Add `muEnableV1FieldEmptyCheck`, `muEnableV2FieldPopulatedCheck`, `muEnableShareIndexNonZero`, `muEnableSplitIDPresent`, `muEnableFieldTagDiscrimination`. Five binding tests, one per constant. `crypto/escrow/vss_v2.go`: already touched by Group 2's migration, now add the audit discipline. Gates: `muEnableEscrowSecretSizeCheck`, `muEnableEscrowDealerDIDNonEmpty`, `muEnableEscrowThresholdBounds`, `muEnableReconstructVersionCheck`, `muEnableReconstructShareVerification`.

**Subgroup 5.3 — Signatures, envelope, SMT.** Four files. `crypto/signatures/entry_verify.go`: every entry on every log passes through this file, so the blast radius is larger than the gate count. Gates: `muEnableEntrySignatureVerify`, `muEnablePubKeyOnCurve`, `muEnableSignatureLength`. `crypto/signatures/bls_verifier.go`: largest file in this subgroup and requires the explicit RFC 9380 carveout. Read-pass identifies the Ortholog-bespoke DSTs (cosignature domain tag, PoP domain tag) versus the IETF-governed hash-to-curve DSTs. Only the Ortholog-bespoke ones migrate to the universal length-prefix rule; the hash-to-curve DSTs stay raw-concat per RFC 9380. Document this carveout in-source at the top of the file with the named function exceptions matching the godoc entry in `crypto/hash.go` from Group 1. Gates: `muEnableBLSSubgroupCheck`, `muEnableBLSPoPVerify`, `muEnableBLSDSTSeparation`, `muEnableBLSAggregateVerify`. Existing tests (`bls_gaps_test.go`, `bls_pop_test.go`, `bls_rogue_key_test.go`, `bls_lock_test.go`) provide significant coverage — audit confirms which map to which gates. `core/envelope/serialize.go`: the canonical-form hash-chain integrity anchor. Any regression here silently breaks log immutability. Gates: `muEnableCanonicalOrdering`, `muEnableSizeCap`, `muEnableVersionReject`, `muEnableDestinationBound`. `core/smt/verify.go`: proof verification. Gates: `muEnableRootMatch`, `muEnableProofDepthBounds`, `muEnableEmptyLeafDistinction`.

**Closure proof.** Eight new `.mutation-audit.yaml` registries. The Group 4 runner passes on all. Every new `muEnable*` has a binding test that genuinely fails when flipped. BLS carveout documented in-source at the top of `bls_verifier.go` and in the audit log, cross-referenced with the `crypto/hash.go` godoc. M4 transcript mutation logged with timestamp. `TestPRE_DLEQTranscript_Golden` has zero `t.Skip` paths. `TestPRE_DecryptFrags_RejectsOffCurveOwnerKey_Isolated` passes.

**Verification for Group 5.** Every primitive-level file has a registry, passes the audit runner, has a dated audit log entry. `grep -rn 't.Skip' --include='*_test.go' crypto/ core/` returns zero matches in cryptographic test files.

---

## Group 6 — Composition Layer Audit

**Packages:** `verifier/`, `witness/`, `lifecycle/`

**Purpose:** Close Phase C's cryptographic scope with the composition-layer audit. Earlier drafts of this plan included a subgroup covering three "builder authorization fixes" sourced from a secondary security review. Re-reading `builder/algorithm.go` against that review refuted all three claims: `PriorAuthority` in this codebase *is* the scope-observation pointer by protocol design (not a multiplex with target OCC), `processPathA` and `processPathB` already reject scope-entity targets, and the new-leaf branch already validates scope membership before committing. The builder is not modified by Phase C per ADR-005 scope boundaries. No `ScopeObservation` field is introduced.

The composition layer audit proceeds against correctly-structured builder output, which means the upstream authorization boundaries the verifier and lifecycle depend on are already enforced at admission time. The audit's job is to confirm the composition-layer primitives correctly consume that upstream enforcement and don't reintroduce gaps via their own logic. Builder files (`algorithm.go`, `entry_builders.go`, `occ_retry.go`, `concurrency.go`) are explicitly deferred to property tests per the expanded-scope ruling and remain deferred.

**Subgroup 6.1 — Verifier and witness audit.** Files: `verifier/cosignature.go` (already well-structured — `IsCosignatureOf` is the canonical predicate per the file's own godoc; audit adds `muEnableCosignatureBinding` with the existing `cmd/lint-cosignature-binding` AST linter as its binding enforcement), `verifier/fraud_proofs.go` (audit equivocation detection gates), `witness/verify.go` and `witness/equivocation.go` (cosignature quorum + equivocation detection), `verifier/cross_log.go` (nine distinct verification steps per the file's godoc, each gated in Group 8 and cross-registered here). `verifier/condition_evaluator.go` and `verifier/contest_override.go` are already heavily test-covered against existing cosignature-binding and sybil-defense regression tests (evidence from file contents — `IsCosignatureOf` routes every cosignature binding check, `authorizedSet` threads the scope-history result through the Sybil defense); these files get a lighter-touch audit focused on confirming existing tests bind to the gates rather than structural refactor. New mutation switches in this subgroup: `muEnableCosignatureBinding`, `muEnableEquivocationDetection`, `muEnableWitnessQuorumCount`, `muEnableFraudProofValidation`. Each gate factored into a named function reading its constant; each switch has a binding test that genuinely fails when flipped.

**Subgroup 6.2 — Lifecycle layer audit with atomic emission coverage.** `lifecycle/artifact_access.go` already threads commitments correctly through `VerifyAndDecryptArtifact` with `ErrMissingCommitments` (evidence from shared contents — PRE mode requires commitments at decrypt time, primitive verifies every CFrag before Lagrange combination); audit adds `muEnableArtifactCommitmentRequired` gating the existing check, plus `muEnableGrantAuthorizationCheck` gating the `CheckGrantAuthorization` dispatch on `GrantAuthorizationMode`. Group 3's `muEnableCommitmentEmissionAtomic` is registered here as part of the lifecycle audit surface — the binding test confirms that a lifecycle function returning shares without a commitment causes downstream admission rejection.

`lifecycle/recovery.go` has `EvaluateArbitration` with three named witness gates per file contents (Gate 1 deserialize, Gate 2 position binding via `IsCosignatureOf`, Gate 3 independence check against `EscrowNodeSet`); add `muEnableWitnessDeserialize`, `muEnableWitnessPositionBinding`, `muEnableWitnessIndependence` and register. The `ErrReconstructedSizeMismatch` defensive invariant (evidence from shared contents — asserts `escrow.Reconstruct` returns exactly `escrow.SecretSize` bytes at the lifecycle boundary) gets `muEnableReconstructSizeCheck`.

`lifecycle/provision.go` and `exchange/identity/mapping_escrow.go` get audit coverage for the escrow-side atomic emission wired in Group 3.5. Parallel `muEnableCommitmentEmissionAtomic` coverage for the escrow path confirms structural atomicity.

**Closure proof.** Four new `.mutation-audit.yaml` registries: `verifier/cosignature.mutation-audit.yaml`, `verifier/fraud_proofs.mutation-audit.yaml` (also covering `verifier/cross_log.go`'s gates registered in Group 8), `witness/verify.mutation-audit.yaml` (covering both witness files), `lifecycle/artifact_access.mutation-audit.yaml` (covering `artifact_access.go`, `recovery.go`, `provision.go`, and `mapping_escrow.go`'s atomic emission gates). Full runner produces a clean audit log for every Tier 1, 2, and 3 file. Every new `muEnable*` has a binding test. Existing regression tests (`TestClassifyPathC_StrictOCCRejectsPriorMismatch`, `condition_evaluator_sybil_test.go`, `contest_override_bug016_test.go`) remain green; audit confirms each binds to a registered gate.

**Verification for Group 6.** Composition layer has registries and audit entries for every applicable file. Zero builder modifications. `grep 'muEnable[A-Za-z]\+\s*=\s*false'` returns zero hits across the composition-layer files. Atomic emission invariant is structurally enforced and test-bound on both escrow and PRE paths.

---

## Group 7 — Destination Binding Universal Enforcement

**Packages:** `core/envelope/destination.go`, `core/envelope/serialize.go`, every builder in `builder/entry_builders.go`, call sites in `lifecycle/`, `exchange/`, `verifier/`

**Purpose:** v7.75 introduces destination binding on every builder. Evidence from `builder/entry_builders.go`: all existing builders (plus the two new commitment-entry builders from Group 3.4) have a `Destination` field and all call `validateCommon(signerDID, destination)` which in turn calls `envelope.ValidateDestination`. The repo root contains `APPLY-destination-binding.md` and `PATCHES-destination-binding.md` (visible in the tree listing), which together suggest the migration is applied but not yet audited across every caller. This group locks the cryptographic property — destination binding is part of the canonical hash — and verifies every external caller supplies a non-zero Destination.

**Subgroup 7.1 — Call-site audit.** Use `cmd/check-sdk-usage/main.go` (already exists in the tree per the listing) to scan every external caller of every builder, including the two new commitment-entry builders. The tool should already have AST-level understanding of the builder signatures; extend it with a `--destination-binding` mode that verifies every `Build*` call site supplies a non-empty string literal or a non-nil variable for `Destination`. Read `APPLY-destination-binding.md` and `PATCHES-destination-binding.md` to understand what's already been done and what's outstanding.

**Subgroup 7.2 — Canonical hash binding verification.** `core/envelope/serialize.go` must include `Destination` in the canonical hash such that two entries differing only in Destination produce different canonical bytes and therefore different hashes. Evidence from the tree: `tests/destination_binding_test.go` exists. Read it and verify coverage is complete — specifically that it tests: (a) same entry with two different Destinations produces two different canonical hashes, (b) tampering with only the Destination byte range in serialized output invalidates deserialize, (c) the validator rejects malformed Destinations (empty string, non-DID format). Add coverage for the two new commitment-entry builders if not already present.

**Subgroup 7.3 — Validator centralization.** `envelope.ValidateDestination` should be the single validator; no file should validate destinations inline. `grep -n 'Destination == ""' --include='*.go'` and `grep -n 'len(.*Destination)' --include='*.go'` catch inline validation. Route any remaining inline checks through the canonical function.

**Closure proof.** `check-sdk-usage --destination-binding` passes with zero unbound call sites across all builders. `TestDestinationBinding_CanonicalHashIncludes` passes (from `tests/destination_binding_test.go`). `grep -n 'Destination == ""' --include='*.go'` returns zero hits outside `core/envelope/destination.go`. Every `Build*` function has a test case covering `ErrEmptyDestination`-equivalent rejection, including the two new commitment-entry builders.

**Verification for Group 7.** Destination binding is universal and cryptographically anchored. No call site in the SDK or its integration tests constructs an entry without a valid Destination. The canonical hash includes Destination bytes and two entries differing only in Destination have provably different hashes.

---

## Group 8 — Cross-Log and Authority Snapshot Verification Lock

**Packages:** `verifier/authority_evaluator.go`, `verifier/cross_log.go`, `witness/verify.go`, `core/envelope/` (read-only)

**Purpose:** Two v7.75 features need lockdown: the authority snapshot shortcut in `verifier/authority_evaluator.go` and the nine-step cross-log proof verification in `verifier/cross_log.go`. The cross-log path is already well-structured — nine explicit binding checks, `ErrExtractorRequired` fail-fast guard, cosignature quorum verification all present in current source; it needs mutation-audit coverage. The authority snapshot path has three concrete defects a close read of the file surfaces: the `ConstraintState` enum zero-value collides with `ConstraintActive` and makes the classification loop's skip-guard silently dead, the snapshot-harvested evidence pointers depend on that dead guard for laundering prevention (creating a refactor trap), and the `EvidencePointers` walk is unbounded because snapshots are exempt from `MaxEvidencePointers` at admission (verifier-side DoS). All three are gating for Phase C closure. ADR-005 §7 locks the two source corrections.

**Subgroup 8.1 — Authority snapshot shortcut audit and hardening.** `verifier/authority_evaluator.go`'s `EvaluateAuthority` walks the `PriorAuthority` chain backward and detects snapshot entries by shape via `isAuthoritySnapshotEntry`. When a snapshot is found, the shortcut iterates `EvidencePointers` as the active constraint set rather than continuing the chain walk. The classification pass runs `scopeMembershipValid` on walked entries: resolves the scope-history primitive at the entry's admission position, reclassifies entries with unauthorized signers to `ConstraintOverridden`. Close reading surfaces three gaps the audit must close.

*Defect 1 — `ConstraintState` zero-value collision.* The enum is currently declared as:

```go
type ConstraintState uint8
const (
    ConstraintActive ConstraintState = iota  // 0
    ConstraintPending                         // 1
    ConstraintOverridden                      // 2
)
```

The classification loop guards with `if allEntries[i].State != 0 { continue }` and comments "Already classified (snapshot entries)." The intent was to skip snapshot entries the shortcut branch had already marked `ConstraintActive`. Because `ConstraintActive` is `0`, the guard never fires — `0 != 0` is false. The code accidentally runs `scopeMembershipValid` on snapshot-harvested entries anyway, which is the desired behavior, but for the wrong reason: a future developer reading the comment and "fixing" the guard to match its stated intent would silently reintroduce the constraint-laundering exploit described in Defect 2. The structural fix is to introduce a distinct zero value. Shift the enum to:

```go
type ConstraintState uint8
const (
    ConstraintUnclassified ConstraintState = iota  // 0
    ConstraintActive                                // 1
    ConstraintPending                               // 2
    ConstraintOverridden                            // 3
)
```

Update the classification guard to `if allEntries[i].State != ConstraintUnclassified { continue }`. Update both the snapshot branch and the non-snapshot branch to leave harvested/walked entries at `ConstraintUnclassified` explicitly (the zero value is already `ConstraintUnclassified` after the shift, so no code change is required at the initialization sites — the invariant is now load-bearing and readable). Callsite sweep: grep for `ConstraintActive\b`, `ConstraintPending\b`, `ConstraintOverridden\b` across `verifier/`, `lifecycle/`, `judicial-network/`; any code that compares against numeric literals rather than named constants must switch to named constants (independent correctness improvement). Any serialization code that encodes `ConstraintState` as a raw byte must be reviewed — numeric values shifted by one, so on-wire or on-disk representations need a migration or a version tag. Binding test: `TestEvaluateAuthority_ClassificationLoopGuardIsLoadBearing` — constructs two entries pre-marked as `ConstraintPending`, confirms the classification loop does not re-classify them; flipping `muEnableClassificationGuard` off short-circuits the guard and the test catches the reclassification.

*Defect 2 — Constraint laundering via snapshot shortcut.* Independent of the enum issue, the snapshot shortcut branch needs an explicit invariant: harvested `EvidencePointers` entries must run through `scopeMembershipValid` on equal footing with the non-snapshot chain walk. Today this happens accidentally because of the dead guard in Defect 1. After the enum shift, it happens deterministically because both branches leave entries at `ConstraintUnclassified` and the classification loop processes every such entry. An authorized attacker signing a valid snapshot and populating `EvidencePointers` with pointers to fraudulent or historically rejected entries signed by unauthorized parties will see those entries reclassified to `ConstraintOverridden` and dropped from the active set. The shortcut remains an O(A) optimization for chain walking; it ceases to be an authorization bypass. Mutation switch `muEnableSnapshotMembershipValidation` gates the classification loop's `scopeMembershipValid` call — flipping it false restores a code path that skips the membership check for harvested entries, and the binding test `TestEvaluateAuthority_SnapshotEvidenceMembershipValidated` confirms laundering succeeds when flipped and fails when restored.

*Defect 3 — CPU exhaustion via unbounded snapshot evidence walk.* The current code runs `for _, evPtr := range entry.Header.EvidencePointers` unconditionally. The envelope writer exempts snapshots from `MaxEvidencePointers` at admission (evidence from `isAuthoritySnapshotShape` in `core/envelope/serialize.go`), which is correct for admission semantics but means the verifier walks whatever length the snapshot claims. A malicious authorized signer publishing a snapshot with 500,000 evidence pointers causes any downstream light client or node running `EvaluateAuthority` to enter an unbounded fetch-and-deserialize loop and crash with OOM or CPU stall. Fix: `MaxSnapshotEvidencePointers = 256` as the verifier-side cap per ADR-005 §7. Exceeding the cap terminates the walk at the boundary. Mutation switch `muEnableSnapshotEvidenceCap` gates the cap; binding test `TestEvaluateAuthority_SnapshotEvidenceCapEnforced` constructs a 10,000-pointer snapshot, confirms the walk terminates at 256 without resource exhaustion.

*Audit coverage for existing correct behavior.* Two additional mutation switches cover logic that's correct today but needs explicit audit coverage. `muEnableSnapshotShapeCheck` gates the `isAuthoritySnapshotEntry` predicate itself; flipping it false admits non-snapshot entries into the shortcut branch and the binding test confirms rejection. `muEnableAuthorityChainCycleGuard` gates the `visited` map check; flipping it false allows corrupted chains to loop and the binding test confirms the `maxAuthorityChainDepth` cap eventually fires instead — this catches a future developer accidentally removing the cycle guard.

**Subgroup 8.2 — Cross-log proof nine-step lock.** Evidence from `verifier/cross_log.go`: the nine-step verification is already well-documented in the file header and already has multiple binding checks (steps 2, 5, 7 bind leaf hashes; step 10 binds anchor payload content to `TreeHeadHash(proof.SourceTreeHead)`). The `ErrExtractorRequired` fail-fast guard exists because a nil extractor would make the step 9 content-binding check reachable only via a nil-deref panic — that guard is already correct and needs a binding test that confirms the fast-fail path fires. Audit adds mutation switches for each verification step: `muEnableSourceEntryNonZero`, `muEnableSourceInclusionBinding`, `muEnableSourceInclusionVerify`, `muEnableSourceHeadCosigVerify`, `muEnableLocalInclusionBinding`, `muEnableLocalInclusionVerify`, `muEnableAnchorBytesHashBinding`, `muEnableAnchorPayloadExtraction`, `muEnableAnchorContentBinding`, `muEnableExtractorRequired`. Binding tests exist in `tests/` (cross-log tests visible in the tree listing); audit confirms each binds to a distinct gate. The `BuildCrossLogProof` constructor explicitly sets `MerkleProof.LeafHash` on both inclusion proofs as a defensive measure against prover implementations that leave it zero — audit documents this as an explicit invariant in a comment and in the mutation-audit YAML.

**Subgroup 8.3 — Witness cosignature quorum lock.** `witness/verify.go` is called from `verifier/cross_log.go` as `witness.VerifyTreeHead(proof.SourceTreeHead, sourceWitnessKeys, sourceQuorumK, blsVerifier)`. Add `muEnableQuorumCount` (verifies at least K unique signatures), `muEnableUniqueSigners` (verifies no signer appears twice in the quorum set), `muEnableWitnessKeyMembership` (verifies every signer's public key is in the provided `sourceWitnessKeys` set). Three binding tests confirm each gate rejects the specific failure mode it guards.

**Closure proof.** Three new `.mutation-audit.yaml` registries: `verifier/authority_evaluator.mutation-audit.yaml` (five switches: `muEnableClassificationGuard`, `muEnableSnapshotMembershipValidation`, `muEnableSnapshotEvidenceCap`, `muEnableSnapshotShapeCheck`, `muEnableAuthorityChainCycleGuard`), `verifier/cross_log.mutation-audit.yaml` (ten switches), `witness/verify.mutation-audit.yaml` (three switches). The `ConstraintState` enum shift is a structural source change with a callsite sweep documented in the commit message; the binding test makes the guard load-bearing and catches future regressions. Three new binding tests for the authority snapshot defects as described above. All nine cross-log verification steps are gated; witness quorum audit completes; full runner passes.

**Verification for Group 8.** Every verification step in the composition layer has an explicit gate and a binding test. The classification loop's skip-guard is now load-bearing — the guard variable name encodes the invariant and the binding test fails if a future refactor breaks it. The constraint laundering exploit is structurally impossible — harvested snapshot entries land at `ConstraintUnclassified` by construction and run through `scopeMembershipValid` in the classification loop. The DoS vector is closed — verifier-side evidence walk is strictly bounded at 256 regardless of admission-time exemption. The authority snapshot shortcut remains an O(A) optimization but ceases to be an authorization bypass or a resource exhaustion vector. Phase C audit log records the enum shift, the two defect fixes, and the binding tests that enforce each.

---

## Group 9 — Phase C Release Engineering

**Packages:** all

**Purpose:** Single closure proof for Phase C. Everything in Groups 1-8 produces localized artifacts (per-file registries, per-group audit log entries, per-subgroup test suites). This group consolidates into one manifest, one tagged release, one audit appendix that is the authoritative record. v7.75 is complete at Phase C close; there is no Phase D.

**Subgroup 9.1 — Manifest generation.** `scripts/verify-phase-c-decomm.sh --full` runs every registry through the Group 4 runner end-to-end, produces a single manifest at `docs/audit/phase-c-manifest.md` enumerating every audited file, every mutation switch, every binding test, every golden fixture, and the dated pass entry for each. This is what the external auditor reviews.

**Subgroup 9.2 — Global grep gates.** The final gates that must all pass: `grep -rn 'muEnable.*=\s*false' --include='*.go'` returns zero. `grep -rn 't\.Skip' --include='*_test.go' crypto/ core/` returns zero matches. `grep -rn 'sha256.Sum256' crypto/ core/ | grep -v LengthPrefixed` reviewed and every remaining hit either migrated or explicitly documented as a non-TupleHash case (e.g., RFC 6962 leaf hash in `core/envelope/` which is protocol-mandated, BLS hash-to-curve in `bls_verifier.go` which is RFC 9380). `grep -rn 'ORTHOLOG-V7.75-ESCROW-SPLIT' --include='*.go'` and `grep -rn 'ORTHOLOG-V7.75-PRE-GRANT-SPLIT-ID-v1' --include='*.go'` each return only the canonical call site and godoc hits. `grep -rn 'EscrowSplitDST' --include='*.go'` returns zero hits.

**Subgroup 9.3 — Phase C documentation.** Update `CHANGES.md` with the Phase C summary: nine groups; audited files across cryptographic primitives and composition layer; mutation switches across Tier 1, Tier 2, and Tier 3; golden fixtures across canonicalization, SplitIDs, KFrag wire, and both commitment types; one canonicalization primitive; one SplitID migration; one universal length-prefix rule; complete commitment-entry surface shipped in-SDK for both subsystems; one `ConstraintState` enum restructure; two authority-evaluator defect fixes. Release tag `v7.75.0-phase-c` applied. Note explicitly: v7.75 is a complete SDK release; operator deployments consume the commitment-entry surface as shipped.

**Closure proof.** `scripts/verify-phase-c-decomm.sh --full` exits zero. Manifest generated. Release tag applied.

**Verification for Group 9.** Phase C closes when the manifest exists, the global grep gates all pass, `CHANGES.md` is updated, and the release tag is applied.

---

## Global Closure Proof

After all nine groups: `scripts/verify-phase-c-decomm.sh --full` completes with zero failures, zero skipped tests. Manifest exists at `docs/audit/phase-c-manifest.md` enumerating every artifact. `grep -rn 'muEnable.*=\s*false' --include='*.go'` returns zero. Every file in the Tier 1/2/3 lists has a dated audit log entry. v7.75 is a complete SDK release; the commitment-entry surface is shipped end-to-end (structs, serializers, verifiers, builders, schemas, atomic emission, lookup primitives) for both escrow and PRE subsystems. Release tag `v7.75.0-phase-c` applied.

## Sequencing Summary

Group 1 → Group 2 → Group 3 → Group 4 → Group 5 → Group 6 → Group 7 → Group 8 → Group 9. Dependencies flow strictly forward. Groups 4-8 admit review parallelism on independent files where audit work does not collide. Phase C closes when Group 9's manifest is signed off.