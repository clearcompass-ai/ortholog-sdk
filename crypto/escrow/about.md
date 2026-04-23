# crypto/escrow

## Purpose

Threshold secret sharing for Ortholog escrow records. Two schemes
coexist in this package:

- **V1** — GF(256) Shamir Secret Sharing (`api.go`).
- **V2** — Pedersen Verifiable Secret Sharing over secp256k1
  (`vss_v2.go`), built on `core/vss`.

Plus per-node share transport (ECIES over secp256k1,
`ecies.go`), a shared wire format (`share_format.go`), pre-
reconstruction validators (`verify_share.go`), and mobile-enclave
blind-routing interfaces (`blind_routing.go`).

Evidence: `api.go:1-54` (package doc enumerating both schemes + the
zeroization primitives).

## The two schemes side-by-side

| Property | V1 — GF(256) Shamir | V2 — Pedersen VSS |
| --- | --- | --- |
| Function | `Split`, `Reconstruct`, `SplitGF256`, `ReconstructGF256` | `SplitV2`, `ReconstructV2`, `VerifyShareAgainstCommitments` |
| Math | `GF(2^8)` byte-wise, reduction polynomial `0x11B` (AES convention) | secp256k1 scalar polynomial + Pedersen commitments |
| Cryptographic share verification | **None** — a substituted share produces a silently-wrong secret; detected only at AES-GCM tag failure downstream with no attribution | Every share verified against the dealer's published commitment set; tampering yields a typed error |
| SplitID | Random 256-bit, fresh per `Split` | Deterministic: `SHA-256(DST \|\| BE_u16(len(did)) \|\| did \|\| nonce)` per ADR-005 §6.1 |
| Threshold enforcement | At the reconstruction boundary (closes BUG-010) | Same, plus polynomial-level gating |
| Constant-time inner loop | `gf256Mul` runs a fixed 8 rounds, no data-dependent branches | N/A (big.Int arithmetic) |
| Status | API frozen — v7.5 consumers unchanged | Shipped in Phase B; wired into lifecycle flows in Phase D |

Evidence: `api.go:168-272` (V1 Split/Reconstruct + threshold-boundary
enforcement), `api.go:288-305` (constant-time `gf256Mul` with
rationale for removing the `for b > 0` early-terminating loop),
`vss_v2.go:29-100` (V2 positioning + deterministic SplitID).

## Wire format (132 bytes, fixed)

`share_format.go` defines a **forward-compatible** layout: V1 and V2
shares share the same envelope; only the interpretation of three
fields changes, keyed on `Version`.

| Offset | Size | Field | V1 | V2 |
| ---: | ---: | --- | --- | --- |
| 0 | 1 | `Version` | `0x01` | `0x02` |
| 1 | 1 | `Threshold` | M | M |
| 2 | 1 | `Index` | x-coordinate 1..255 | x-coordinate 1..255 |
| 3 | 32 | `Value` | GF(256) y-bytes | secp256k1 scalar `f(i) mod n` |
| 35 | 32 | `BlindingFactor` | zeros | Pedersen `r_i` |
| 67 | 32 | `CommitmentHash` | zeros | SHA-256 of commitment set |
| 99 | 32 | `SplitID` | random 256-bit | derived (see §6.1) |
| 131 | 1 | `FieldTag` | `0x01` (`SchemeGF256Tag`) | reserved for Pedersen |

`ShareWireLen = 132` (grew from 131 in v7.5 when `FieldTag` was
added).

A V1 reader rejects V2 shares until V2 ships. A future V2 reader will
reject V1 outright — no V1 shares exist at rest, so there's no
backward-compatibility requirement.

Evidence: `share_format.go:21-75` (layout + version constants).

## Zeroization — authoritative primitives

This package OWNs the SDK's zeroization discipline. Every file inside
escrow **and** every external consumer routes secret-buffer clearing
through these functions rather than writing ad-hoc loops.

| Primitive | Contract |
| --- | --- |
| `ZeroBytes([]byte)` | `go:noinline`, calls `runtime.KeepAlive` after the loop. Variable-length. |
| `ZeroArray32(*[32]byte)` | `go:noinline`, nil-safe (defer chains can't always statically prove non-nil). |
| `ZeroizeShare(*Share)` | Clears EVERY field, including structural metadata (Version, Threshold, Index). A zeroed share is distinguishable from a live one. Nil-safe. |
| `ZeroizeShares([]Share)` | Loops `ZeroizeShare`. |

Go does not guarantee zeroization even with these steps (stack copies,
register spills, GC relocation, OS paging are all out of user
control). This is the best portable pure-Go approach.

Evidence: `api.go:68-145`.

## Validators (`verify_share.go`)

| Export | Role |
| --- | --- |
| `ValidateShareFormat(Share) error` | Per-share structural check. Dispatches on `Version`: V1 requires V2-only fields be zero; V2 requires them non-zero. Common gates: `Threshold >= 2`, `Index != 0`, `SplitID != 0`. |
| `VerifyShareSet([]Share) error` | Set-level: all shares agree on Version/Threshold/SplitID; indices unique; set size meets declared Threshold (closes BUG-010). |

**Naming note.** The previous function was called `VerifyShare`, which
implied cryptographic verification that V1 does not provide. V1 is a
structural check only; actual cryptographic verification requires
Pedersen commitments and lands with V2
(`VerifyShareAgainstCommitments`). The rename reflects reality.

Evidence: `verify_share.go:1-60`.

## Per-node transport (`ecies.go`)

ECIES over secp256k1 for encrypting individual shares to escrow node
public keys. Uses the same curve as entry signatures, witness
cosignatures, and Umbral PRE.

- Scheme: ephemeral ECDH → SHA-256 KDF → AES-256-GCM.
- Wire format: `[65 bytes ephemeral pubkey][12 bytes nonce][ct+tag]`;
  overhead `65 + 12 + 16 = 93` bytes. A 131-byte share becomes 224
  bytes on the wire.
- Every on-curve check is performed before `ScalarMult` — an off-curve
  point yields an undefined ECDH result that would poison the KDF
  input.
- Scalars are padded to 32 bytes before `ScalarMult`; `big.Int.Bytes()`
  strips leading zeros, which would change `~1/256` of results.
- v7.75 Phase A′ migrated this file from `github.com/dustinxie/ecc` to
  `github.com/decred/dcrd/dcrec/secp256k1/v4` to align with the rest
  of the SDK. **Wire format unchanged**; only the backing library
  differs.

Evidence: `ecies.go:1-90`.

## V2 — additional invariants (`vss_v2.go`)

- Domain separation tag: `"ORTHOLOG-V7.75-ESCROW-SPLIT"` (27 bytes
  ASCII). Changing it invalidates every escrow SplitID ever produced
  — protocol version bump, not a routine change.
- `ComputeEscrowSplitID(dealerDID, nonce)` is exposed so Phase D
  builders (and tests/auditors reproducing fixtures) don't reimplement
  the derivation.
- NFC normalisation of `dealerDID` is the **caller's** responsibility
  (ADR-005 §6.5). Phase B does not force it — that would pull in
  `golang.org/x/text` for a property SDK-produced DIDs already
  satisfy.
- `SplitV2` uses `crypto/rand`; deterministic tests go through the
  unexported `splitV2WithReader` with a seeded DRBG so production
  flows stay on the CSPRNG.
- Honest-dealer assumption: `SplitV2` runs in SDK-controlled processes
  (provisioning, key rotation, grant emission). A malicious dealer
  who publishes inconsistent commitments causes reconstruction to
  **fail** (not produce a wrong secret); the equivocation itself is
  signed evidence handled at the lifecycle / witness layer per
  ADR-005 §7.4.

Phase D consumers: `exchange/identity/mapping_escrow.go`,
`lifecycle/provision.go`, `lifecycle/recovery.go`.

Evidence: `vss_v2.go:1-98`.

## Mobile enclave blind-routing (`blind_routing.go`)

Thin scaffolding used by higher-level mobile flows:

- `EnclaveAttestation` interface (`VerifyAttestation`, `Platform`).
- `BlindRouteShares func(encryptedBlobs) (*BlindRouteResult, error)`
  — injection point for the routing implementation.
- `MockAppleAttestation`, `MockAndroidAttestation` — test doubles
  returning `"apple_secure_enclave_mock"` / `"android_strongbox_mock"`.

Evidence: `blind_routing.go:1-24`.

## Errors (sentinels)

Surfaced so callers distinguish structural vs. semantic failure shapes
(`errors.Is`-dispatchable):

- `ErrInvalidThreshold`, `ErrBelowThreshold`, `ErrInsufficientShares`,
  `ErrThresholdMismatch`, `ErrMixedThresholds`,
  `ErrUnsupportedVersion`, `ErrUnknownFieldTag`, …

`ReconstructGF256` re-tags known failure modes into the explicit-
scheme sentinels (`ErrInsufficientShares`, `ErrMixedThresholds`),
wrapping the original so `errors.Is` still matches the underlying
sentinel.

Evidence: `api.go:390-413`.

## Dependencies

- `core/vss` — Pedersen VSS primitive backing V2.
- `github.com/decred/dcrd/dcrec/secp256k1/v4` — curve for V2 and
  ECIES.
- `crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/sha256`,
  `crypto/ecdsa`, `crypto/elliptic`, `encoding/binary`, `io`,
  `runtime` (stdlib).

## Tests

- `api_test.go`, `share_format_test.go`, `verify_share_test.go` — V1
  split/reconstruct, wire round-trips, per-share + set-level
  validation including BUG-010 boundary cases.
- `vss_v2_test.go` — V2 split/reconstruct + substitution detection.
- `ecies_test.go`, `ecies_oncurve_test.go` — ECIES round-trip +
  off-curve rejection.
- `blind_routing_test.go` — mock attestation happy-path / empty-input
  rejection.
- `testhelpers_test.go` — shared fixtures.
