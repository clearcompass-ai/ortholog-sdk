# Ortholog SDK — Web3 Refactor Apply Instructions

This bundle contains the complete, production-grade web3 refactor of the
Ortholog SDK. No backward compatibility shims. No legacy wrappers.

All files in this bundle are authoritative — drop them into place, run the
mechanical rename below, update `go.mod`, and the refactor is complete.

---

## Prerequisites

Go 1.21+ is required (uses stdlib `crypto/ed25519` and `crypto/elliptic`
features).

---

## 1. Bundle file → repo path mapping

Every file in this bundle sits at the repo-relative path its header declares.
Flat copy from `ortholog-web3/` onto the repo root:

```bash
cp -r ortholog-web3/* /path/to/ortholog-sdk/
```

Files in this bundle, in the order they were created:

| Bundle path                                         | Status       |
| --------------------------------------------------- | ------------ |
| `crypto/signatures/ethereum_primitives.go`          | **new**      |
| `crypto/signatures/eip191.go`                       | **new**      |
| `crypto/signatures/eip712.go`                       | **new**      |
| `crypto/signatures/verify_primitives.go`            | **new**      |
| `crypto/signatures/entry_verify.go`                 | replaces existing (logic unchanged, doc clarified) |
| `core/envelope/signature_wire.go`                   | replaces existing (adds EIP-191 and EIP-712 algo IDs) |
| `did/method_router.go`                              | **new**      |
| `did/key_resolver.go`                               | **new**      |
| `did/pkh.go`                                        | **new**      |
| `did/pkh_verifier.go`                               | **new**      |
| `did/key_verifier.go`                               | **new**      |
| `did/web_verifier.go`                               | **new**      |
| `did/verifier_registry.go`                          | **new**      |
| `did/creation.go`                                   | replaces existing (rewritten) |
| `did/resolver.go`                                   | replaces existing (rewritten) |
| `exchange/auth/signed_request.go`                   | **new**      |

---

## 2. Dependency additions

From repo root:

```bash
go get golang.org/x/crypto@latest
go get github.com/decred/dcrd/dcrec/secp256k1/v4@latest
go get github.com/mr-tron/base58@latest
go mod tidy
```

The existing `github.com/dustinxie/ecc` dependency is **retained** — it still
provides the secp256k1 curve implementation used by `entry_verify.go`.

Full rationale: see `go.mod.additions.txt`.

---

## 3. Mechanical rename: CredentialRef → EntryRef

`exchange/identity/mapping_escrow.go` and its test file contain the
`CredentialRef` symbol. Rename mechanically:

```bash
cd /path/to/ortholog-sdk

# Rename the type and every reference in one shot.
find . -type f -name '*.go' \
    -exec sed -i 's/\bCredentialRef\b/EntryRef/g' {} +
```

After the rename, verify no residual references:

```bash
grep -rn --include='*.go' '\bCredentialRef\b' .
# (should print nothing)
```

While editing `exchange/identity/mapping_escrow.go`, update the package
doc comment to reflect the exchange-as-relay reframing:

```go
// Package identity provides entity authentication orchestration and
// domain identity verification flows. The exchange acts as a message
// relay (analogous to an MX record or a telephone exchange), not a
// key custodian — entities hold their own keys via wallets, KMS, or
// smart accounts.
```

The test file should be similarly updated: `tests/mapping_escrow_test.go`
uses `CredentialRef` values; the same `sed` command above covers it.

---

## 4. Wiring at service startup

Typical deployment bootstrap after applying this bundle:

```go
import (
    "github.com/clearcompass-ai/ortholog-sdk/did"
)

// --- DID resolution router ---
webResolver := did.NewWebDIDResolver(nil) // default 15s HTTP timeout
router := did.NewMethodRouter()
router.MustRegister("web", webResolver)
router.MustRegister("key", did.NewKeyResolver())
router.MustRegister("pkh", did.NewPKHResolver())

// Wrap with TTL cache for steady-state resolution traffic.
cachedResolver := did.NewCachingResolver(router, 5*time.Minute)

// --- Signature verifier registry ---
verifierRegistry := did.DefaultVerifierRegistry(cachedResolver)

// Verify an entry signature (did:pkh, did:key, or did:web):
err := verifierRegistry.Verify(signerDID, canonicalHash[:], sig, algoID)
```

---

## 5. Signer-side client code

### Sign an entry hash via EIP-712 (wallet)

Client-side helper — call from a dApp's wallet-integration layer:

```go
import "github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"

// Canonical entry hash computed by the SDK's envelope layer.
canonical := [32]byte{...}

// 32-byte digest to pass to eth_signTypedData_v4. The wallet UI renders
// "OrthologEntry" typed data. The wallet signs this digest.
digest := signatures.EntrySigningDigest(canonical)

// Or for personal_sign (EIP-191):
digest := signatures.EIP191Digest(canonical[:])
```

The returned 65-byte signature (`r || s || v`) is attached with algorithm ID
`envelope.SigAlgoEIP712` or `envelope.SigAlgoEIP191` respectively.

### Generate a did:key identity (no wallet needed)

```go
kp, err := did.GenerateDIDKeyEd25519()     // Ed25519
kp, err := did.GenerateDIDKeySecp256k1()   // secp256k1 (KMS / Ethereum-compatible)
kp, err := did.GenerateDIDKeyP256()        // P-256 (passkey-compatible)
```

Each returns a concrete-typed keypair. No type assertions at the call site.

---

## 6. Sanity checks after applying

### Build

```bash
go build ./...
```

Expected: clean build. If you see import-cycle errors, double-check that
`crypto/signatures/*.go` does NOT import the `did/` package (the registry
lives in `did/` specifically to avoid this cycle).

### Algorithm ID regression

EIP-712 domain constants are frozen forever. Lock them with a regression
test. The expected hex values for:

```go
signatures.EIP712DomainSeparator()  // fixed constant for life of protocol
signatures.EIP712EntryTypeHash()    // keccak256("OrthologEntry(bytes32 canonicalHash)")
signatures.EIP712ProtocolSalt()     // keccak256("ortholog.v1.entry-signature")
```

A CI test that locks these against known-good hex values prevents accidental
modification of the frozen constants.

### Language sweep

The previous codebase contained judicial-network / credentialing /
physician / court references in doc comments. Sweep with:

```bash
grep -rn --include='*.go' -iE 'judicial|consortium|credentialing|physician|court' . \
  | grep -v tests/  \
  | grep -v '\.md:'
```

Replace with entity-neutral language:

| Old term              | Replacement                        |
| --------------------- | ---------------------------------- |
| judicial network      | entity network                     |
| credentialing platform| entity identity provider           |
| consortium            | entity federation                  |
| physician             | entity (or the specific entity kind) |
| court                 | upstream authority                 |

Test fixtures (e.g., `did:web:court.example.com`) do NOT need renaming as
they do not leak into the public API.

---

## 7. Tests to add

Add these tests to lock behavior. Paths suggested; adapt to your layout.

- `tests/eip712_domain_test.go` — locks domain separator, type hash, salt.
- `tests/key_resolver_test.go` — generates did:key for each curve, parses
  round-trip, rejects unsupported multicodecs and non-'z' multibase.
- `tests/pkh_resolver_test.go` — parses CAIP-10 identifiers, rejects
  unsupported namespaces, mixed-case hex acceptance.
- `tests/verifier_registry_test.go` — end-to-end for each DID method:
  generate key → sign canonical hash → verify through registry.
- `tests/signed_request_test.go` — exercises envelope replay protection,
  expiry, domain binding, nonce store.

---

## 8. What this refactor explicitly does NOT provide

These are out of scope for this bundle. If you need them, they should be
separate follow-on work:

- **did:ethr resolver**. Requires an ERC-1056 registry + chain RPC. Distinct
  runtime characteristics from the static resolvers in this bundle.
- **A NonceStore implementation**. The `NonceStore` interface is defined in
  `exchange/auth/signed_request.go` but the implementation belongs to the
  exchange service (Redis, Postgres, in-memory LRU — site-specific).
- **Non-EVM did:pkh verifiers**. Solana, Cosmos, and Bitcoin signature
  verification require dedicated libraries and verification functions.
  The `PKHResolver` can be constructed with additional namespaces via
  `NewPKHResolverWithNamespaces`, but the `PKHVerifier` hard-codes
  `eip155`. Extending requires new primitives.
- **ERC-4337 smart-account signature verification**. Smart account
  signatures use `isValidSignature(bytes32,bytes) → 0x1626ba7e` per
  EIP-1271; verification requires an RPC call to the wallet contract.
  That is a separate verifier implementation (`SmartAccountVerifier`) that
  registers alongside `PKHVerifier`.

---

## 9. Architectural invariants locked by this bundle

These are protocol-level commitments. Changing any invalidates existing
signatures.

1. **`VerifyEntry(hash, sig, pubkey)` signature is stable.** Witness
   cosignature verification (`witness_verify.go`) depends on it. Do not
   alter the function signature.

2. **`envelope.SigAlgoECDSA == 0x0001` and `SigAlgoEd25519 == 0x0002`.**
   Both wire constants retain their meaning. Adding `SigAlgoEIP191 == 0x0003`
   and `SigAlgoEIP712 == 0x0004` is purely additive.

3. **EIP-712 domain is frozen forever:**
   - `name    = "Ortholog"`
   - `version = "1"`
   - `chainId = 0` (chain-agnostic protocol)
   - `verifyingContract = 0x0000000000000000000000000000000000000000`
   - `salt    = keccak256("ortholog.v1.entry-signature")`
   Struct type: `OrthologEntry(bytes32 canonicalHash)`.

4. **`did:key` uses multibase 'z' (base58btc) + multicodec prefixes only.**
   The legacy non-standard `did:key:f<hex>` format is gone. Any old
   identifiers in storage must be re-issued.

5. **`did:pkh` uses CAIP-10 `eip155:<chainId>:<address>` format only.**
   Non-EVM namespaces can be parsed but not verified.

---

## 10. Post-apply verification checklist

```bash
# Build clean
go build ./...

# No stale CredentialRef references
grep -rn --include='*.go' '\bCredentialRef\b' . | grep -v '_test.go'  # empty expected

# No stale "did:key:f" legacy format references outside of migration tests
grep -rn --include='*.go' '"did:key:f' .  # empty expected

# No DID-method string branching leaked outside did/
grep -rn --include='*.go' 'strings\.HasPrefix.*"did:' . | grep -v '^\./did/' | grep -v '_test.go'
# (empty expected)

# Test suite green
go test ./...
```

If all four pass, the refactor is complete.
