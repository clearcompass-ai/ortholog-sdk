# crypto/artifact

## Purpose

Two layered cryptographic concerns for artifact payloads:

1. **Storage encryption (at rest)** — AES-256-GCM wrapping of raw
   artifact bytes with a freshly generated per-artifact key
   (`api.go`).
2. **Access control (who can decrypt)** — Umbral Threshold Proxy
   Re-Encryption on secp256k1 with Pedersen VSS binding, per ADR-005
   (`pre.go`).

The two are composable: Umbral wraps/transforms the AES key; schemas
declare which access model applies via `aes_gcm | umbral_pre`.

Evidence: `pre.go:1-10` (package doc: "AES-256-GCM = storage
encryption (artifact at rest, permanent); Umbral PRE = access control
(who can decrypt, additive); Composable: Umbral wraps/transforms the
AES key").

## Surface

### Storage encryption (`api.go`)

| Export | Role |
| --- | --- |
| `EncryptArtifact(plaintext) (ct, ArtifactKey, err)` | Fresh 32-byte key + 12-byte nonce via `crypto/rand`, then AES-256-GCM seal. |
| `DecryptArtifact(ct, ArtifactKey) ([]byte, error)` | AES-256-GCM open. Failures are wrapped as `IrrecoverableError`. |
| `ReEncryptArtifact(ct, oldKey) (newCT, newKey, err)` | Decrypt → re-encrypt with fresh key. Intermediate plaintext is zeroed via a `defer` registered immediately after decrypt so every exit path is covered. `runtime.KeepAlive` defeats dead-store elimination. |
| `VerifyAndDecrypt(ct, key, artifactCID, contentDigest)` | Defense-in-depth: verifies storage integrity (ct matches `artifactCID`) before decryption, then verifies plaintext matches `contentDigest` after. On content-digest failure, zeroes the plaintext before returning the error. |
| `ZeroKey(*ArtifactKey)` | `go:noinline`, nil-safe in-place zeroization of Key and Nonce. |
| `IrrecoverableError`, `NewIrrecoverableError`, `IsIrrecoverable`, `ErrIrrecoverableNilCause` | Marks failures that retry cannot fix (AES key corruption, GCM tag mismatch, hash mismatch). Callers distinguish transient vs. permanent via `errors.As` / `IsIrrecoverable`. Both `Error()` and `Unwrap()` handle a nil `Cause` symmetrically so literal-construction misuse is still detectable via `ErrIrrecoverableNilCause`. |

Evidence: `api.go:15-114` (storage primitives), `api.go:80-85`
(zeroization defer), `api.go:116-136` (VerifyAndDecrypt),
`api.go:149-197` (IrrecoverableError).

### Access control — Umbral PRE (`pre.go`)

| Export | Role |
| --- | --- |
| `PRE_Encrypt(pk, plaintext) (*Capsule, ct, err)` | Ephemeral ECDH → SHA-256 KDF → AES-256-GCM. Capsule is storable in Domain Payload; DH shared secret is NEVER stored — `V = r·U` where `U = hashToPoint(pk_owner)` binds the capsule to the owner without leaking the shared secret. |
| `PRE_Decrypt(sk, capsule, ct)` | Direct decryption by the owner. No re-encryption. |
| `PRE_GenerateKFrags(skOwner, pkRecipient, M, N) ([]KFrag, vss.Commitments, err)` | Produces N re-encryption key fragments + the Pedersen commitment set. Blinding scalar `b_i` is owner-local: computed, consumed to produce `BK_i`, then zeroized. It never enters a KFrag and never reaches a proxy. |
| `PRE_ReEncrypt(kfrag, capsule, commitments) (*CFrag, error)` | Proxy side. Produces a `CFrag` with DLEQ proof computed over the locked transcript (`vss.DLEQChallenge`) that absorbs the commitment set and `BK_i`. |
| `PRE_VerifyCFrag(cfrag, capsule, commitments)` | Dual gate: (1) DLEQ — proxy used a consistent `rk_i` for both `VK_i = rk_i·G` and `E' = rk_i·E`; (2) Pedersen — `(VK_i, BK_i)` lies on the committed polynomial, `VK_i + BK_i = Σ i^j·C_j`. Either failing rejects the CFrag. |
| `PRE_DecryptFrags(skRecipient, cfrags, capsule, ct, pkOwner, commitments)` | **Verify-then-combine-then-decrypt.** Every CFrag is verified against the commitment set BEFORE Lagrange combination. A caller that forgets verification cannot reintroduce the substitution attack. |
| `SerializeCFrag`, `DeserializeCFrag` | Fixed 196-byte wire encoding per ADR-005 §8.3. Reserved bytes (32) are checked first for cheap rejection before curve arithmetic. |
| `ZeroizeKFrag(*KFrag)` | Lifecycle-end zeroization of `RKShare` (best-effort on `*big.Int`) + `BK` bytes. Safe on nil. |

Evidence: `pre.go:398-555` (encrypt/decrypt/GenerateKFrags),
`pre.go:903-987` (VerifyCFrag / DecryptFrags with gate ordering),
`pre.go:995-1096` (wire (de)serialization).

## Wire format (ADR-005 §8.3)

`CFrag` = 196 bytes:

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 33 | `E'` (compressed secp256k1) |
| 33 | 33 | `VK` (compressed) |
| 66 | 33 | `BK` (compressed) |
| 99 | 1 | `ID` (share index; 0 reserved) |
| 100 | 32 | `ProofE` (DLEQ challenge, F_n) |
| 132 | 32 | `ProofZ` (DLEQ response, F_n) |
| 164 | 32 | Reserved (MUST be zero) |

Evidence: `pre.go:39-58`, `pre.go:298-312`.

## The substitution attack this package closes

DLEQ alone is insufficient (M proxies can agree on a forged `rk'` and
produce mutually-consistent DLEQ proofs). Pedersen alone is
insufficient (a proxy could present a valid `(VK, BK)` pair without
having used `rk_i` for re-encryption). Only requiring **both** checks,
and requiring them **before** Lagrange combination, closes the KFrag-
substitution attack that ADR-005 exists to prevent.

Evidence: `pre.go:14-37` (package-doc explanation of the attack),
`pre.go:188-200` (mutation-audit commentary on the Pedersen gate — its
tests name the attack: `TestPRE_CoalitionAttack_Rejected`,
`TestPRE_SubstitutedRKShare_Rejected`).

## Mutation-audit switches

`pre.go` declares six `muEnable*` compile-time constants — one per
security gate. Setting any to `false` disables a production gate and
the SDK becomes exploitable. Their sole purpose is the per-release
mutation discipline audit required by ADR-005 §9.2: each switch lists
the exact tests that MUST fail when it is flipped. A release is
blocked if the listed tests still pass with a gate disabled (the tests
are fake and the SDK is provably untested).

Production invariant: every `muEnable*` MUST be `true` on any
committed code. A pre-commit / CI grep for `muEnable.*= false` is
intended (see `scripts/ci-check.sh`).

The gates:
`muEnableCommitmentsGate`, `muEnableOnCurveGate`, `muEnableDLEQCheck`,
`muEnablePedersenCheck`, `muEnableSufficientCFragsGate`,
`muEnableVerifyBeforeCombine`.

Evidence: `pre.go:95-235`.

## Zeroization reality check

The Go runtime makes no guarantee that secret bytes are erased from
heap memory after a variable goes out of scope. Callers zero 32-byte
scalar/coordinate slices on the best-effort path, but intermediate
`*big.Int` allocations are opaque to user code and may persist until
GC. Deployments with strict zeroization requirements MUST run
`sk_owner` operations inside a hardware enclave (HSM or TEE) where the
secret never enters Go-managed memory.

Evidence: `pre.go:60-70`.

## Types

- `Capsule { EX, EY, VX, VY, CheckVal }` — public, storable. Contains
  only curve points, no private material.
- `KFrag { ID, RKShare, VKX, VKY, BK[33] }` — re-encryption key
  fragment. `RKShare` is the secret share scalar.
- `CFrag { EPrimeX, EPrimeY, ID, VKX, VKY, BK[33], ProofE, ProofZ }` —
  ciphertext fragment produced by `PRE_ReEncrypt`.
- `ArtifactKey { Key[32], Nonce[12] }` — AES-256-GCM material.

## Dependencies

- `github.com/decred/dcrd/dcrec/secp256k1/v4` — curve.
- `core/vss` — Pedersen VSS split + polynomial verification +
  `DLEQChallenge` (locked transcript).
- `storage` — `CID` type used in `VerifyAndDecrypt`.
- `crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/sha256`,
  `crypto/elliptic` (stdlib).

## Tests

- `api_test.go` — AES-GCM round-trip, re-encrypt, error paths,
  irrecoverable-error semantics.
- `pre_test.go` — end-to-end Umbral flows + every substitution /
  coalition attack the mutation-audit switches call out.
- `pre_oncurve_test.go` — on-curve / off-curve boundary cases for
  `VK`, `E'`, capsule `E`, and `BK`.
