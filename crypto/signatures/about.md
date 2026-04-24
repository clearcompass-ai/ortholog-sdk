# crypto/signatures

## Purpose
Provides the pure mathematical signature primitives for **entry signatures** (secp256k1, Ed25519, P-256) and **witness cosignatures** (aggregate ECDSA and BLS12-381).

It owns the Ethereum-compatible digests (EIP-191, EIP-712) and low-level primitives (Keccak256, ecrecover) required by the `did:pkh` verifier. Multi-sig loop execution belongs to the `did/` package; this package strictly verifies the underlying math.

## Signature Schemes & Functional Behavior

### SDK-Native secp256k1
* `SignEntry` produces a 64-byte low-S raw $R \parallel S$ signature, closing malleability vectors.
* `VerifyEntry` verifies 64-byte raw signatures but does *not* enforce low-S on verification, explicitly to support KMS-backed and external wallet signers that may legitimately produce high-S forms.

### Ethereum Primitives (EIP-191 & EIP-712)
Supports `personal_sign` and typed-data digests. `VerifySecp256k1EIP191` and `VerifySecp256k1EIP712` expect 65-byte ($r \parallel s \parallel v$) signatures, executing `ecrecover` and an address comparison rather than pubkey-based verification (as the address *is* the identity for `did:pkh`).

### BLS12-381 (Witness Aggregation)
Implements BLS12-381 for optimistic $K$-of-$N$ threshold aggregate signatures.
* **Subgroup Validation:** Every $G1$ signature and $G2$ public key is checked for prime-order subgroup membership at parse time to defeat small-subgroup attacks.
* **Proof of Possession (PoP):** Security depends strictly on PoP at registration. Without PoP, an attacker can construct a rogue key to force a unilateral forgery.

### The RFC 9380 Hash-to-Curve Carveout
BLS verification relies on Domain Separation Tags (DSTs).
1. **The IETF Exemption:** The standard suite IDs embedded inside `expand_message_xmd` (e.g., `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`) strictly follow the RFC 9380 hash-to-curve spec. They **DO NOT** route through the SDK's `LengthPrefixed` helper to maintain global interoperability.
2. **Ortholog-Bespoke Tags MUST Migrate:** The application-layer `BLSDomainTag` and `BLSPoPDomainTag` used to namespace Ortholog-internal signatures are **NOT** exempt. To prevent boundary-shifting collisions during entry and tree-head compositions, these bespoke tags MUST be passed into the `LengthPrefixed` TupleHash helper prior to verification.
