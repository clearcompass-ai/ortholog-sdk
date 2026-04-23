# crypto/signatures

## Purpose

Signature primitives for **entry signatures** (per-signer, secp256k1
/ Ed25519 / P-256) and **witness cosignatures** (aggregate ECDSA and
BLS12-381). Also owns the Ethereum-compatible digests (EIP-191,
EIP-712) and the low-level Ethereum primitives (Keccak256,
ecrecover, address derivation) the `did:pkh` verifier depends on.

Entry-level multi-sig **verification** (iterating `entry.Signatures`
and routing each to a DID-method verifier) lives in
`did/verifier_registry.go`, not here, because that path must import
DID-method knowledge — and `did/` already imports this package for
key-pair primitives. The two `VerifyEntry` identifiers don't collide:
one is `signatures.VerifyEntry` (free function), the other is
`(*did.VerifierRegistry).VerifyEntry` (method).

Evidence: `entry_verify.go:17-30` (note on the package-cycle reason).

## Surface by concern

### SDK-native secp256k1 (`entry_verify.go`)

| Export | Role |
| --- | --- |
| `Secp256k1() elliptic.Curve` | Curve accessor returning the stdlib interface so callers don't depend on the concrete `decred *KoblitzCurve`. |
| `GenerateKey() (*ecdsa.PrivateKey, error)` | Delegates to decred's `secp256k1.GeneratePrivateKey` + `ToECDSA()`. |
| `ParsePubKey(bytes)` | Accepts 65-byte uncompressed (`0x04`) **and** 33-byte compressed (`0x02/0x03`) forms. |
| `PubKeyBytes(pub) []byte` | 65-byte uncompressed form; pads X and Y to exactly 32 bytes (fixes `big.Int.Bytes()` stripping leading zeros that would break fixed-width consumers like `AddressFromPubkey`). |
| `VerifyEntry(hash, sig, pub)` | 64-byte raw `R‖S` ECDSA. Rejects zero R or S. **Does NOT enforce low-S on verify** — KMS-backed / wallet signers may produce high-S form legitimately. |
| `SignEntry(hash, privkey)` | Produces 64-byte low-S raw `R‖S`. Low-S closes the malleability class where `(r, s)` and `(r, n-s)` both verify but have distinct byte representations. |

### Per-algorithm verifier primitives (`verify_primitives.go`)

One function per `(curve, encoding, message-construction)` tuple —
**no polymorphic "verify any signature"** because that enables
downgrade attacks.

- `VerifySecp256k1Raw(addr, hash, sig65)` — wallet signed the 32-byte
  canonical hash directly.
- `VerifySecp256k1EIP191(addr, hash, sig65)` — `personal_sign`.
- `VerifySecp256k1EIP712(addr, hash, sig65)` — typed-data digest.
- `VerifySecp256k1Compressed(pubBytes, hash, sig)` — `did:key` path
  (multicodec `0xe701`).
- `VerifyEd25519(pubBytes, message, sig)` — stdlib `crypto/ed25519`
  (multicodec `0xed01`).
- `VerifyP256(pubBytes, hash, sig)` — stdlib `crypto/ecdsa` +
  `elliptic.P256()` (multicodec `0x1200`).

All three secp256k1 wallet variants take a 65-byte Ethereum-format
signature (`r‖s‖v`) and do **ecrecover + address compare**, not
pubkey-based verify — for `did:pkh` the DID **is** the address, so
address equality is the only meaningful check.

Low-S is **not** enforced in the EIP-191 / EIP-712 paths: Ethereum
wallets don't enforce it on user-visible signatures, and rejecting
high-S here would reject legitimate wallet output. Entry signatures
produced by SDK keys do enforce low-S — that's `SignEntry`'s job.

Evidence: `verify_primitives.go:10-54`.

### Ethereum primitives (`ethereum_primitives.go`)

Three pieces that compose the Ethereum signature verification path:

1. `Keccak256(...[]byte) [32]byte` — via
   `golang.org/x/crypto/sha3.NewLegacyKeccak256` (original Keccak,
   pre-SHA-3 standardization — SHA3-256 output is different and **not**
   compatible).
2. `RecoverSecp256k1(digest, sig65)` — via
   `github.com/decred/dcrd/dcrec/secp256k1/v4`, chosen over
   `go-ethereum/crypto` to avoid pulling the Ethereum client as a
   dependency. Decred's impl is the upstream for `btcec/v2`.
3. `AddressFromPubkey(uncompressed) [20]byte` — last 20 bytes of
   `Keccak256(uncompressed_pubkey[1:])`; the `0x04` prefix byte is
   dropped before hashing.

Accepts `v ∈ {0,1}` and `v ∈ {27,28}` conventions both. Fails loudly
on malformed input — no silent fallbacks.

Evidence: `ethereum_primitives.go:1-38`.

### EIP-191 (`eip191.go`)

Only version `0x45` (the letter "E") — the `personal_sign` variant
every EVM wallet uses (MetaMask, Ledger, Rainbow, Coinbase,
WalletConnect). Version `0x00` (data-with-intended-validator) and
`0x01` (alias for EIP-712) are **not** implemented — they have their
own flows.

```
prefix = "\x19Ethereum Signed Message:\n" + decimal_ascii(len(message))
digest = keccak256(prefix || message)
```

Length prefix is **decimal ASCII**, not hex. For Ortholog entry
signing via EIP-191 the wallet signs over the 32-byte canonical entry
hash; the verifier reconstructs the digest and runs ecrecover.

Evidence: `eip191.go:1-59`.

### EIP-712 (`eip712.go`)

Frozen protocol domain. Every parameter is a **constant that MUST
NEVER change** — changing any of them invalidates every signature
ever produced against the protocol. Regression tests lock the values.

- `name` = `"Ortholog"`
- `version` = `"1"` (see `EIP712DomainVersion`)
- `chainId` = `0` (chain-agnostic — Ortholog is a protocol, not a
  contract)
- `verifyingContract` = zero address (same reason)
- `salt` = `keccak256("ortholog.v1.entry-signature")`

Struct type is minimal: `OrthologEntry(bytes32 canonicalHash)`. The
canonical hash commits to everything else. Wallet UIs that support
named display wrap this with richer display types, but the
reconstructable typed data has exactly this one field.

Evidence: `eip712.go:1-60`.

### Witness cosignature signing + dispatch (`witness_verify.go`)

Two signing schemes currently dispatched:

- `SchemeECDSA` (`0x01`) — secp256k1, 64-byte raw `R‖S` via
  `SignEntry`.
- `SchemeBLS` (`0x02`) — aggregate BLS via an injected verifier.

**Wave 2 change — per-signature dispatch.** Pre-Wave-2 this file had
two monolithic helpers that each verified ALL signatures in a
cosigned head under a single scheme (read from `head.SchemeTag`).
That forced every witness in a head to use the same scheme. Post-
Wave-2, the dispatcher reads each signature's `SchemeTag`
independently: a single head can mix schemes. ECDSA verifies inline
one at a time; BLS queues for batched aggregate verification so the
O(1)-pairing optimistic path still applies.

Hardening:

- **Strict zero-tag rejection.** `SchemeTag == 0` → typed error
  before any cryptographic work. No defensive populate, no
  "migration fallback."
- **Strict unknown-tag rejection.** Unrecognized tags are rejected
  with a typed error; future scheme additions must propagate through
  the dispatcher's `switch` deliberately.

Only ECDSA signing (`SignWitnessCosignature`) is exported here — the
BLS path is implementation-defined by the injected verifier.

Evidence: `witness_verify.go:1-70`.

### BLS12-381 signing (`bls_signer.go`)

**Curve choice.** BLS12-381 — industry-standardized (Ethereum
Pectra/EIP-2537, ZetaChain, Filecoin, drand, Chia), 128-bit security,
native in gnark-crypto, first-class RFC 9380 hash-to-curve. BN254
was rejected: 100-bit security is insufficient for a 10+ year
horizon, and its main advantage (Ethereum precompile cost) is
irrelevant to an off-chain verifier.

**Group assignment.** Signatures on G1 (48 bytes compressed), public
keys on G2 (96 bytes compressed). Matches Ethereum consensus +
ZetaChain's deployed pattern + gnark ergonomics. Signatures dominate
wire traffic; keys are a per-witness one-time cost.

**Aggregate, not threshold.** Each witness holds an independent
keypair. No DKG ceremony. Rotation / onboarding / offboarding are
per-witness. K-of-N quorum is counted by the verifier, not
cryptographically aggregated. Tradeoff: slightly larger cosignatures
(K × 48 bytes vs a single 48-byte threshold sig) in exchange for
operational simplicity and heterogeneous-witness-set forward
compatibility.

**Two DSTs, not one.** `BLSDomainTag` for cosignature signing,
`BLSPoPDomainTag` for proof-of-possession. Domain separation blocks
cross-protocol signature reuse — a witness induced to sign arbitrary
bytes under `BLSDomainTag` cannot have that signature replayed as a
PoP, and vice versa. This is security-critical for rogue-key
attack prevention.

**Version locking.** Both DSTs are scheme-version-locked to V1
(`"ORTHOLOG_BLS_SIG_V1_"`, 20 bytes). Changing either is a breaking
protocol change that must increment the scheme version (e.g. to
`SchemeBLS_V2 = 0x04`) rather than modify V1 in place. Byte-level
locks live in `bls_lock_test.go`.

**Exports.** `SignBLSCosignature(head, privKey)`,
`SignBLSPoP(pk, sk)`, `GenerateBLSKey()`, `BLSPubKeyBytes(pk)`,
`ParseBLSPubKey(bytes)`.

Evidence: `bls_signer.go:18-88`.

### BLS12-381 verification (`bls_verifier.go`)

`GnarkBLSVerifier` implements the `BLSVerifier` interface
(`witness_verify.go`) using `github.com/consensys/gnark-crypto`.

- **Optimistic aggregation with per-signature attribution
  fallback.** Happy path: one pairing check regardless of witness
  count N — left side sums signatures, right side sums public keys,
  bilinearity makes the equation balance when all signatures are
  valid. Sad path (optimistic check fails): N individual pairing
  checks to identify **exactly which signatures failed**.
- **Security depends on PoP at registration.** The aggregate
  algorithm is sound only when every pubkey has been verified for
  proof-of-possession. Without PoP, an attacker constructs a rogue
  key `pk_rogue = g2^x − Σ pk_others` whose aggregate collapses to a
  key whose discrete log the attacker knows — unilateral forgery.
  `VerifyBLSPoP` is provided here; the registrar MUST call it before
  admitting any public key.
- **Subgroup validation at every decompression.** Every G1 signature
  and G2 public key is checked for prime-order subgroup membership at
  parse time. Skipping this enables small-subgroup attacks that
  spuriously satisfy the aggregate pairing.
- **Failure isolation.** One malformed signature or public key
  doesn't corrupt aggregation — the bad entry is marked invalid and
  excluded; monitoring services can distinguish "one witness sent
  garbage" from "the whole cosignature is bad."
- **No mutable state.** `GnarkBLSVerifier` holds nothing across
  calls; safe to share across goroutines.

Evidence: `bls_verifier.go:20-51`.

## Algorithm-ID and curve summary

| AlgoID / scheme | Curve | Signature | Public key | Digest |
| --- | --- | --- | --- | --- |
| `SigAlgoECDSA` | secp256k1 | 64-byte `R‖S` low-S (SDK) / raw (wallet/KMS) | 65-byte uncompressed (SDK) or recovered from `did:pkh` | `SHA-256(canonical)` |
| `SigAlgoEIP191` | secp256k1 | 65-byte `r‖s‖v` | recovered via ecrecover | EIP-191 `personal_sign` digest |
| `SigAlgoEIP712` | secp256k1 | 65-byte `r‖s‖v` | recovered via ecrecover | EIP-712 typed-data digest |
| `did:key` secp256k1 | secp256k1 | (as above) | 33-byte compressed | SHA-256 |
| Ed25519 (`did:key` multicodec `0xed01`) | Ed25519 | 64 bytes | 32 bytes | N/A (signs message) |
| P-256 (`did:key` multicodec `0x1200`) | P-256 | DER-encoded ECDSA | 33/65-byte SEC1 | SHA-256 |
| `SchemeECDSA` (witness cosig, `0x01`) | secp256k1 | 64-byte `R‖S` | per-witness | head-level |
| `SchemeBLS` (witness cosig, `0x02`) | BLS12-381 | 48-byte compressed G1 | 96-byte compressed G2 | RFC 9380 hash-to-G1 |

## Dependencies

- `github.com/decred/dcrd/dcrec/secp256k1/v4` — secp256k1 + recovery.
- `github.com/consensys/gnark-crypto/ecc/bls12-381` (+ `.../fr`) —
  BLS12-381 curve, pairings, subgroup checks, RFC 9380 hash-to-curve.
- `golang.org/x/crypto/sha3` — legacy Keccak256.
- `crypto/ecdsa`, `crypto/ed25519`, `crypto/elliptic`,
  `crypto/sha256` (stdlib).
- `types.TreeHead`, `types.WitnessCosignMessage`,
  `types.WitnessSignature`, `types.WitnessPublicKey`.

## Tests

- `bls_benchmark_test.go` — aggregate-verify benchmarks.
- `bls_gaps_test.go` — coverage holes from the Wave-1/Wave-2
  refactor.
- `bls_lock_test.go` — byte-level locks on hash-to-G1 output and both
  DSTs.
- `bls_pop_test.go` — proof-of-possession happy-path + tamper
  rejection.
- `bls_rogue_key_test.go` — rogue-key attack rejected when PoP is
  enforced.
- `bls_verifier_test.go` — aggregate / individual fallback /
  failure-isolation paths.
- `witness_verify_test.go` — per-signature dispatch, zero-tag
  rejection, unknown-tag rejection, mixed-scheme heads.
