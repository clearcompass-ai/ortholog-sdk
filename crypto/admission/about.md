# crypto/admission

## Purpose

Implements **Ortholog Mode B admission stamps** — a proof-of-work gate
submitters attach to entry headers so operators can throttle write
pressure without distributing write credits. Mode A (credential-based
admission) never reaches this package; it is handled upstream in the
operator's admission layer. This package owns Mode B only.

Evidence: `stamp.go:283` (`ErrStampModeMismatch` — "Mode A entries never
reach VerifyStamp — the operator's admission layer handles Mode A via
write-credit validation before this function is called").

## Surface

| Export | Role |
| --- | --- |
| `GenerateStamp(StampParams) (uint64, error)` | Submitter side. Iterates nonces from 0 upward, returns the first nonce whose stamp hash has the required leading-zero bits. |
| `VerifyStamp(proof, entryHash, expectedLogDID, minDifficulty, hashFunc, argonParams, currentEpoch, acceptanceWindow)` | Operator side. Validates mode, target-log match, difficulty floor, epoch window, and the recomputed hash. |
| `ProofFromWire(body, targetLog) *types.AdmissionProof` | Adapter that turns an `envelope.AdmissionProofBody` (wire form inside entry headers) into the API form `VerifyStamp` consumes. |
| `CurrentEpoch(windowSeconds) uint64` | Helper: `floor(unix_seconds / windowSeconds)`. Returns 0 when `windowSeconds == 0` (disabled) or when the system clock is pre-Unix-epoch (misconfiguration guard). |
| `HashSHA256 / HashArgon2id` (`HashFunc`) | Selects the stamp hash primitive. |
| `WireByteHashSHA256 / WireByteHashArgon2id` | `uint8` aliases used by external code building `envelope.AdmissionProofBody`. Locked numerically equal to the typed `HashFunc` constants by `wire_encoding_test.go`. |
| `DefaultArgon2idParams()` | Protocol default: `Time=1`, `Memory=64 MiB`, `Threads=4`. |
| `DefaultEpochWindowSeconds=300`, `DefaultEpochAcceptanceWindow=1` | Default epoch width (5 min) and tolerance (±1 epoch). |

Evidence: `stamp.go:103-116` (HashFunc), `stamp.go:143-161`
(WireByte aliases), `stamp.go:222-250` (epoch helpers),
`stamp.go:375-497` (GenerateStamp / VerifyStamp), `adapter.go:17`
(ProofFromWire).

## Hash input layout

Fixed-width, deterministic:

```
entry_hash(32) || nonce(8) || did_len(2) || did(N) ||
epoch(8) || commit_present(1) || commit(32)
```

- `did_len` uses a `uint16` BE prefix (max 65535 bytes — matches the
  envelope serializer's limit).
- The `SubmitterCommit` slot is **always 32 bytes**. The presence byte
  distinguishes "absent" (`0`, slot zero-filled) from "present and
  happens to be all zeros" (`1`, slot zero-filled).

Evidence: `stamp.go:197-216` (layout constants), `stamp.go:514-552`
(`buildHashInputBuffer`).

## Domain separation

Argon2id runs with a fixed salt: `"ortholog-admission-v1"`. The `-v1`
suffix partitions outputs from this protocol from outputs of any other
protocol reusing Argon2id, and marks the current layout version. Any
layout change MUST bump the salt (`-v2`, `-v3`, …).

Evidence: `stamp.go:190-194`.

## Named errors

Every failure mode is a named sentinel (`errors.Is`-dispatchable)
rather than a string, so operators can map failures to HTTP status
codes or audit categories without string parsing:

`ErrStampDifficultyOutOfRange`, `ErrStampEmptyLogDID`,
`ErrStampLogDIDTooLong`, `ErrStampNilProof`, `ErrStampModeMismatch`,
`ErrStampTargetLogMismatch`, `ErrStampDifficultyBelowMin`,
`ErrStampEpochOutOfWindow`, `ErrStampHashBelowTarget`,
`ErrStampUnknownHashFunc`, `ErrStampNonceExhausted`.

Evidence: `stamp.go:264-310`.

## Architectural decisions (as written in the source)

- **`StampParams` struct over positional arguments.** Eight positional
  parameters is a readability failure; named fields make call sites
  self-documenting and future additions non-breaking.
- **Argon2id invoked directly via `argon2.IDKey`.** A prior
  `MemoryHardHasher` indirection was removed — it was hypothetical-HSM
  plumbing with no caller. If `HashArgon2id` is requested, Argon2id is
  what runs; no silent SHA-256 fallback.
- **`acceptanceWindow == 0` disables the epoch check.** The intuitive
  spelling; prevents the footgun where 0 otherwise means "strictest
  possible" (exact epoch match).
- **Wire-byte aliases + regression test.** Pre-v0.1.1 operators had to
  read source to discover the wire encoding; `wire_encoding_test.go`
  now fails the SDK build if aliases drift from the typed constants.

Evidence: `stamp.go:15-48` (decisions header),
`stamp.go:136-140` (wire-byte history note).

## Dependencies

- `golang.org/x/crypto/argon2` — canonical RFC 9106 Argon2id.
- `types/admission.go` — `AdmissionProof` / `AdmissionMode` wire types.
- `core/envelope` — `AdmissionProofBody` wire struct (via
  `adapter.go`).

## Tests

- `stamp_test.go` — generation + verification round-trips, difficulty
  edges, epoch window, error-path coverage.
- `wire_encoding_test.go` — locks `uint8(HashSHA256) ==
  WireByteHashSHA256` and the Argon2id counterpart.
