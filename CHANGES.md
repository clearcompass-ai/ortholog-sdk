# Ortholog SDK — Authoritative Change Set

This archive contains the production-grade implementation of SDK-1 through SDK-4.
No backward-compatibility shims; no deprecated paths.

## Files delivered

| Path | Status | Purpose |
|------|--------|---------|
| `go.mod` | updated | Adds `golang.org/x/crypto` dependency for Argon2id |
| `go.sum` | updated | Checksums for new dependencies |
| `types/admission.go` | rewritten | `AdmissionProof` with `Epoch` and `SubmitterCommit *[32]byte` |
| `crypto/admission/stamp.go` | rewritten | `StampParams`, direct Argon2id, named errors, fixed-length hash input |
| `crypto/admission/stamp_test.go` | new | 34 test cases covering generate/verify, epochs, hash-input invariants |
| `core/envelope/api.go` | updated | Protocol version 4; exports `MaxCanonicalBytes`, `MaxDelegationPointers` |
| `core/envelope/serialize.go` | rewritten | Length-prefixed admission proof body; forward-compatible |
| `core/envelope/serialize_test.go` | new | 14 test cases including Authority_Skip isolation invariant |
| `lifecycle/difficulty.go` | rewritten | `DifficultyConfig` with epoch parameters |
| `lifecycle/difficulty_test.go` | new | 10 test cases covering config validation and round-trip |

## Files that must be DELETED from the old SDK

- Nothing from this change set creates the `crypto/admission/argon2id_default.go`
  file from the first revision of the plan. Do not create it. Argon2id is called
  directly from `computeStampHash`.

## Breaking changes vs the current SDK

1. **Protocol version bumped from 3 to 4.** Any v3 wire bytes are rejected.
2. **`types.AdmissionProof`** gains `Epoch uint64` and `SubmitterCommit *[32]byte`.
3. **`admission.GenerateStamp`** and **`admission.VerifyStamp`** take new signatures.
   Old callers must migrate to `StampParams` and the new verification parameter list.
4. **`admission.MemoryHardHasher` and `SetMemoryHardHasher` are deleted.**
   Argon2id is wired directly through `golang.org/x/crypto/argon2`.
5. **`lifecycle.DifficultyConfig`** gains `EpochWindowSeconds` and `EpochAcceptanceWindow`.
   `GenerateAdmissionStamp` gains a required `submitterCommit *[32]byte` parameter
   (pass `nil` when not using submitter binding).
6. **Admission proof wire format is length-prefixed.** The outer reader now
   consumes exactly the advertised number of bytes; future additions to the
   admission proof body do not corrupt `Authority_Skip` or any field after it.

## Verification performed

```
$ go build ./...                   # clean, no warnings
$ go vet ./...                     # clean, no findings
$ go test ./...                    # 58/58 passing
$ go test -race ./...              # 58/58 passing under race detector
```

## Test inventory

- **`crypto/admission/stamp_test.go`**: 34 cases
  - Round-trip SHA-256 with and without submitter commit
  - Round-trip Argon2id
  - Hash-below-target detection on nonce and entry-hash tampering
  - Every named error path (`ErrStampDifficultyOutOfRange`, `ErrStampEmptyLogDID`,
    `ErrStampLogDIDTooLong`, `ErrStampUnknownHashFunc`, `ErrStampNilProof`,
    `ErrStampModeMismatch`, `ErrStampTargetLogMismatch`, `ErrStampDifficultyBelowMin`,
    `ErrStampEpochOutOfWindow`, `ErrStampHashBelowTarget`)
  - Epoch window boundary: inside window passes, outside window rejected,
    window=0 disables check
  - Hash-input uniqueness: absent commit vs present-zero commit produce
    different hashes; DID length-prefix eliminates boundary collisions
  - Leading-zero-bit correctness across edge cases

- **`core/envelope/serialize_test.go`**: 14 cases
  - Round-trip for minimal, admission-proof-with-commit, admission-proof-without-commit
  - **`TestAuthoritySkipUnaffectedByExtendedAdmissionProof`** — the critical
    invariant test: an admission proof body extended by 20 unknown bytes still
    parses correctly and `Authority_Skip` survives intact
  - Protocol version rejection (v3 bytes fail to parse)
  - Truncation detection (preamble, body, admission proof body)
  - Invalid commit presence flag rejection
  - `NewEntry` validation: empty `Signer_DID`, Mode B without `TargetLog`,
    non-ASCII DID in strict mode, too many `Evidence_Pointers`
  - Constants sanity check

- **`lifecycle/difficulty_test.go`**: 10 cases
  - Config validation for every invalid input
  - Round-trip with and without submitter commit
  - Epoch binding fully disabled (both sides `= 0`)
  - Wrong target log rejection (`ErrStampTargetLogMismatch`)
  - `DefaultDifficultyConfig` sanity

## Architectural invariants enforced

1. **Fail-fast, no silent fallbacks.** Argon2id failure is unreachable because
   Argon2id is always compiled in; there is no "hasher not registered" condition
   to fall back from.
2. **Fixed-length hash input.** Every stamp hash input has a deterministic
   layout: `entry_hash(32) || nonce(8) || did_len(2) || did(N) || epoch(8) ||
   commit_present(1) || commit(32)`. The commit slot is always 32 bytes;
   zero-filled when absent. The presence byte distinguishes absent from
   present-and-zero.
3. **DID length prefix in hash input.** Different DIDs of different lengths
   cannot produce the same hash input through byte concatenation artifacts.
4. **Domain-separation salt.** Argon2id uses the constant salt
   `ortholog-admission-v1`. The version suffix is the anchor for any future
   hash-input layout change.
5. **Type-enforced commit width.** `SubmitterCommit *[32]byte` means "nil or
   exactly 32 bytes" — no runtime length checks needed downstream.
6. **Forward-compatible wire format.** The admission proof body is length-
   prefixed; extending it in the future does not corrupt adjacent fields.
7. **Acceptance-window-zero disables.** `EpochAcceptanceWindow = 0` means
   "epoch check disabled." `0` is the intuitive default for "off" and removes
   the footgun where a config-typo'd 0 would otherwise mean "strictest possible".
