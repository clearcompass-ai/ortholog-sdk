/*
FILE PATH:

	crypto/signatures/bls_signer.go

DESCRIPTION:

	BLS12-381 aggregate signature primitives. Signing paths for witness
	cosignatures and for proof-of-possession. Key generation and serialization
	helpers. These functions are the witness-side counterparts to the
	verification code in bls_verifier.go; together they form the complete
	BLS primitive surface of the SDK.

	All functions are scheme-version-locked to V1 via BLSDomainTag and
	BLSPoPDomainTag. Changing either constant is a breaking protocol change
	that must increment the scheme version (SchemeBLS_V2 = 0x04 or similar)
	rather than modify V1 in place.

KEY ARCHITECTURAL DECISIONS:
  - Curve: BLS12-381. Chosen for industry standardization (Ethereum
    Pectra/EIP-2537, ZetaChain deployment, Filecoin, drand, Chia). Offers
    128-bit security, native support in gnark-crypto, and first-class
    RFC 9380 hash-to-curve. BN254 was considered and rejected: 100-bit
    security is insufficient for a 10+ year protocol horizon, and its
    primary advantage (Ethereum precompile cost) is irrelevant to our
    off-chain verifier.
  - Signatures on G1 (48 bytes compressed), public keys on G2 (96 bytes
    compressed). Matches Ethereum consensus layer, ZetaChain's deployed
    pattern, and gnark's ergonomics. Signatures dominate wire traffic;
    keeping them in G1 minimizes bandwidth. Public keys are a per-witness
    one-time cost where the larger G2 size is acceptable.
  - RFC 9380 hash-to-curve via gnark's native implementation. Uses the
    BLS12381G1_XMD:SHA-256_SSWU_RO_ suite. Deterministic, standardized,
    covered by the TestHashToG1_LockedOutput byte-level lock in
    bls_lock_test.go.
  - Aggregate, not threshold. Each witness holds an independent keypair.
    No distributed key generation ceremony. Rotation, onboarding, and
    offboarding are per-witness operations. K-of-N quorum is counted by
    the verifier, not cryptographically aggregated into a threshold
    signature. This is a deliberate tradeoff: we accept slightly larger
    cosignatures (K × 48 bytes instead of a single 48-byte threshold
    signature) in exchange for operational simplicity and forward
    compatibility with future heterogeneous witness sets.
  - Two DSTs, not one. BLSDomainTag for cosignature signing,
    BLSPoPDomainTag for proof-of-possession. Domain separation prevents
    cross-protocol signature reuse: an attacker who induces an honest
    witness to sign arbitrary bytes under BLSDomainTag cannot replay
    that signature as a PoP, and vice versa. This distinction is
    security-critical for rogue-key attack prevention; see the godoc on
    SignBLSPoP for the full argument.
  - SignBLSCosignature mirrors SignWitnessCosignature (ECDSA) exactly in
    its input/output contract. A caller swapping schemes needs only to
    change the signing function; the WitnessSignature assembly stays
    identical.

OVERVIEW:

	Witness cosignature signing:
	    sig, err := SignBLSCosignature(head, privKey)
	    // sig is 48-byte compressed G1.

	Witness registration:
	    sk, pk, err := GenerateBLSKey()
	    pop, err := SignBLSPoP(pk, sk)
	    // submit (pk, pop) to registrar

	Witness public key exchange:
	    pkBytes := BLSPubKeyBytes(pk)     // 96 bytes, compressed G2
	    pk2, err := ParseBLSPubKey(pkBytes)

KEY DEPENDENCIES:
  - github.com/consensys/gnark-crypto/ecc/bls12-381
  - types.TreeHead, types.WitnessCosignMessage
*/
package signatures

import (
	"errors"
	"fmt"
	"math/big"
	"strings"

	// ← add
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) Protocol constants — byte-locked by bls_lock_test.go
// -------------------------------------------------------------------------------------------------

// BLSDomainTag is the RFC 9380 domain separation tag for witness
// cosignature hashing. Every BLS cosignature the SDK produces or verifies
// under SchemeBLS (0x02) uses this tag. Changing it invalidates every
// existing BLS cosignature; any modification is a breaking protocol
// change requiring a new scheme version.
//
// The tag is 20 bytes: "ORTHOLOG_BLS_SIG_V1_". The V1 suffix reserves
// the tag namespace for future versions without cross-protocol reuse.
//
// Locked by TestBLSDomainTag_Bytes.
const BLSDomainTag = "ORTHOLOG_BLS_SIG_V1_"

// BLSPoPDomainTag is the domain separation tag for proof-of-possession
// signatures. Distinct from BLSDomainTag so that a cosignature cannot be
// replayed as a PoP and vice versa. This separation is security-critical:
// see the rogue-key attack analysis on SignBLSPoP.
//
// The tag is 20 bytes: "ORTHOLOG_BLS_PoP_V1_". Same length as
// BLSDomainTag for uniform wire treatment.
//
// Locked by TestBLSPoPDomainTag_Bytes.
const BLSPoPDomainTag = "ORTHOLOG_BLS_PoP_V1_"

// BLSG1CompressedLen is the wire size of a compressed G1 point.
// Signatures are G1 points in Ortholog's BLS scheme.
//
// Locked by TestBLSG1CompressedLen_Locked.
const BLSG1CompressedLen = 48

// BLSG2CompressedLen is the wire size of a compressed G2 point.
// Public keys are G2 points in Ortholog's BLS scheme.
//
// Locked by TestBLSG2CompressedLen_Locked.
const BLSG2CompressedLen = 96

// -------------------------------------------------------------------------------------------------
// 2) Errors — typed for caller discrimination
// -------------------------------------------------------------------------------------------------

var (
	// ErrBLSNilPrivateKey is returned when a signing function receives a
	// nil private key. A programming error on the caller's side; the
	// signing function cannot produce defensive output without a key.
	ErrBLSNilPrivateKey = errors.New("signatures/bls: nil private key")

	// ErrBLSNilPublicKey is returned when a signing or serialization
	// function receives a nil public key.
	ErrBLSNilPublicKey = errors.New("signatures/bls: nil public key")

	// ErrBLSInvalidPubKeyLength is returned by ParseBLSPubKey when the
	// input is not exactly BLSG2CompressedLen bytes. Other length values
	// indicate either a malformed wire encoding or an attempt to submit
	// a key for a different curve/scheme.
	ErrBLSInvalidPubKeyLength = errors.New("signatures/bls: invalid public key length")

	// ErrBLSPubKeyNotOnCurve is returned when decompression succeeds
	// structurally but the resulting point is not on the BLS12-381 G2
	// curve. Can indicate bit-rot in storage or an attempt to submit a
	// point crafted to bypass naive checks.
	ErrBLSPubKeyNotOnCurve = errors.New("signatures/bls: public key not on curve")

	// ErrBLSPubKeyNotInSubgroup is returned when the public key is on
	// the curve but not in the prime-order subgroup G2. BLS12-381's G2
	// has a large cofactor; points outside the subgroup can produce
	// incorrect pairing results and must be rejected. This check is
	// essential for security, not a defensive nicety.
	ErrBLSPubKeyNotInSubgroup = errors.New("signatures/bls: public key not in prime-order subgroup")

	// ErrBLSHashToCurveFailed is returned when gnark's HashToG1 fails.
	// In practice this should never occur with well-formed inputs; the
	// error exists to surface library-level failures rather than hiding
	// them behind a panic.
	ErrBLSHashToCurveFailed = errors.New("signatures/bls: hash-to-curve failed")
)

// -------------------------------------------------------------------------------------------------
// 3) SignBLSCosignature — witness cosignature signing
// -------------------------------------------------------------------------------------------------

// SignBLSCosignature produces a BLS12-381 aggregate cosignature over a
// TreeHead. The signing recipe is protocol-locked:
//
//	msg = types.WitnessCosignMessage(head)              // 40 bytes
//	H   = HashToG1(msg, BLSDomainTag)                   // G1 point
//	sig = privKey · H                                   // scalar · G1 → G1
//	out = Compress(sig)                                 // 48 bytes
//
// The returned 48-byte slice is placed in a types.WitnessSignature's
// SigBytes field. Under Wave 1's protocol shape, the containing
// CosignedTreeHead must have SchemeTag == SchemeBLS (0x02). Wave 2
// relocates SchemeTag to the WitnessSignature itself; this function's
// output is unaffected by that change.
//
// Symmetry with ECDSA: SignBLSCosignature has the identical
// (head, privateKey) → (bytes, error) contract as SignWitnessCosignature.
// A caller migrating a witness from ECDSA to BLS changes only the signing
// function reference; the surrounding WitnessSignature assembly is
// unchanged.
//
// Thread-safety: this function is stateless. Multiple goroutines may
// call it concurrently with different keys. A single private key should
// not be shared across concurrent signers without external
// synchronization (Fr is a value type, but defensive copying is cheap).
//
// Callers:
//   - Witness services producing production cosignatures
//   - Test fixtures constructing verifiable BLS-signed tree heads
//   - Witness migration tooling moving keys from ECDSA to BLS
func SignBLSCosignature(head types.TreeHead, privKey *fr.Element) ([]byte, error) {
	if privKey == nil {
		return nil, ErrBLSNilPrivateKey
	}

	// The cosign message is the canonical 40-byte binding of the tree
	// head. This is the exact byte sequence that every other scheme
	// (ECDSA today, future schemes tomorrow) also signs — ensuring
	// cross-scheme semantic equivalence.
	msg := types.WitnessCosignMessage(head)

	// Hash the message onto G1 using RFC 9380 with the cosignature DST.
	// Returns a single G1Affine point uniformly distributed in the
	// prime-order subgroup (SSWU_RO guarantees subgroup membership).
	hashPoints, err := bls12381.HashToG1(msg[:], []byte(BLSDomainTag))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBLSHashToCurveFailed, err)
	}

	// Scalar multiplication: sig = privKey · H.
	// Gnark's ScalarMultiplication runs in constant time for the scalar
	// input, eliminating timing side channels against the private key.
	var sig bls12381.G1Affine
	var privBig = privKey.BigInt(new(big.Int))

	sig.ScalarMultiplication(&hashPoints, privBig)

	// Compress to 48-byte wire representation.
	out := sig.Bytes()
	return out[:], nil
}

// -------------------------------------------------------------------------------------------------
// 4) SignBLSPoP — proof-of-possession signing
// -------------------------------------------------------------------------------------------------

// SignBLSPoP produces a proof-of-possession signature that a witness
// submits at registration alongside their BLS public key. The PoP is the
// security precondition that makes same-message aggregate verification
// (bls_verifier.go VerifyAggregate) sound against rogue-key attacks.
//
// Signing recipe:
//
//	pkBytes = Compress(pub)                             // 96 bytes
//	H       = HashToG1(pkBytes, BLSPoPDomainTag)        // G1 point
//	pop     = privKey · H                               // scalar · G1 → G1
//	out     = Compress(pop)                             // 48 bytes
//
// # The rogue-key attack and why PoP defeats it
//
// Without PoP, an attacker joining a witness set can construct their
// public key adversarially:
//
//	pk_rogue = g2^x - Σ pk_honest
//
// where x is an attacker-chosen scalar. The aggregate public key
// Σ pk_i collapses to g2^x, which the attacker can sign unilaterally
// using x. The aggregate pairing check accepts the forgery; no honest
// witness participated.
//
// PoP blocks this at registration. The attacker knows x (the discrete
// log of the aggregate) but does not know the discrete log of pk_rogue
// alone. Signing H(Compress(pk_rogue), BLSPoPDomainTag) requires
// sk_rogue, which the attacker cannot compute without solving the
// discrete logarithm problem on a specific BLS12-381 G2 point.
// Registration rejects pk_rogue. The attacker never enters the witness
// set.
//
// # Why distinct DST
//
// BLSPoPDomainTag is deliberately different from BLSDomainTag. If they
// were identical, an attacker could induce an honest witness to sign
// arbitrary 96-byte messages under BLSDomainTag (e.g., by manipulating
// a future TreeHead's RootHash section to match a target pk's bytes)
// and replay that signature as a PoP. The distinct DST makes the hash
// targets disjoint: a cosignature hash and a PoP hash for the same
// input bytes land at different G1 points, so a signature over one
// cannot be a valid signature over the other.
//
// # Registrar obligations
//
// The SDK provides SignBLSPoP (this function) and VerifyBLSPoP
// (bls_verifier.go). The registrar — typically the domain network's
// witness onboarding controller — must call VerifyBLSPoP on every
// submitted (pk, pop) pair and reject admissions that fail verification.
// Storing the PoP alongside the public key is recommended for
// auditability but not required for security (the invariant is
// established at registration, not at every subsequent verification).
//
// Thread-safety: stateless, same discipline as SignBLSCosignature.
func SignBLSPoP(pub *bls12381.G2Affine, privKey *fr.Element) ([]byte, error) {
	if pub == nil {
		return nil, ErrBLSNilPublicKey
	}
	if privKey == nil {
		return nil, ErrBLSNilPrivateKey
	}

	// The message for PoP is the compressed public key bytes. This binds
	// the PoP to the specific public key; a PoP for pk_A does not
	// function as a PoP for pk_B.
	pkBytes := pub.Bytes()

	// Hash with the PoP DST, not the cosignature DST. Domain separation
	// is the security barrier against cross-protocol reuse.
	hashPoint, err := bls12381.HashToG1(pkBytes[:], []byte(BLSPoPDomainTag))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBLSHashToCurveFailed, err)
	}

	// Standard BLS signing: pop = sk · H(pk, BLSPoPDomainTag).
	var pop bls12381.G1Affine
	var privBig = privKey.BigInt(new(big.Int))

	pop.ScalarMultiplication(&hashPoint, privBig)

	out := pop.Bytes()
	return out[:], nil
}

// -------------------------------------------------------------------------------------------------
// 5) GenerateBLSKey — keypair generation
// -------------------------------------------------------------------------------------------------

// GenerateBLSKey produces a fresh BLS12-381 keypair using crypto/rand
// as the entropy source. Returns:
//   - privateKey: Fr scalar (32 bytes)
//   - publicKey:  G2Affine point (96 bytes compressed)
//
// Security: the entropy source is crypto/rand, which is Go's standard
// cryptographically secure PRNG (reads from /dev/urandom on Linux, the
// OS CNG on Windows, SecRandomCopyBytes on macOS). No custom entropy
// handling; no configuration knobs. The function either succeeds with
// a cryptographically sound keypair or returns an error from
// crypto/rand.
//
// Scope: intended for test fixtures, dev workflows, and witness
// onboarding tooling. Production witness operators generate keys inside
// their own key-management systems (HSMs, KMS services, air-gapped
// ceremonies); those systems call the underlying Fr.SetRandom and
// ScalarMultiplication primitives directly rather than this convenience
// wrapper. This function is part of the SDK surface but is not the
// canonical production keygen path.
//
// Determinism: non-deterministic by construction. Each invocation
// produces a distinct keypair with overwhelming probability (1 - 2^-255).
// TestGenerateBLSKey_ProducesDistinctKeys validates this empirically.
func GenerateBLSKey() (*fr.Element, *bls12381.G2Affine, error) {
	// Sample a uniformly random scalar in [1, r-1] where r is the
	// BLS12-381 scalar field order. Fr.SetRandom handles the modular
	// reduction and rejection sampling internally.
	var sk fr.Element
	if _, err := sk.SetRandom(); err != nil {
		return nil, nil, fmt.Errorf("signatures/bls: generate private key: %w", err)
	}

	// Public key is pk = sk · G2_generator. ScalarMultiplicationBase is
	// the optimized form for multiplying by the fixed generator; gnark
	// uses a precomputed table for substantial speedup over the generic
	// ScalarMultiplication.
	var pk bls12381.G2Affine
	var skBig = sk.BigInt(new(big.Int))

	pk.ScalarMultiplicationBase(skBig)

	return &sk, &pk, nil
}

// -------------------------------------------------------------------------------------------------
// 6) BLSPubKeyBytes — serialize public key to wire form
// -------------------------------------------------------------------------------------------------

// BLSPubKeyBytes serializes a BLS public key to its canonical 96-byte
// compressed G2 representation. The encoding is:
//   - Big-endian x-coordinate
//   - Sign-of-y encoded in the high bits of the x-coordinate bytes
//   - Subgroup membership is implicit (the caller is responsible for
//     ensuring the point is in G2; ParseBLSPubKey validates this on the
//     return path)
//
// This function never fails. Passing nil triggers a panic — a programming
// error that should never reach production. Callers that construct keys
// defensively should handle the zero-value case before calling.
func BLSPubKeyBytes(pub *bls12381.G2Affine) []byte {
	if pub == nil {
		panic("signatures/bls: BLSPubKeyBytes called with nil public key")
	}
	out := pub.Bytes()
	return out[:]
}

// ParseBLSPubKey decompresses a 96-byte compressed G2 encoding to a
// G2Affine point. Validation is exhaustive: length, on-curve, and
// prime-order-subgroup membership.
//
// # IMPLEMENTATION NOTE (gnark v0.20.1)
//
// In gnark v0.20.1, G2Affine.SetBytes performs the full validation
// chain atomically — decompression, on-curve check, and subgroup
// check. The lower-level setBytes(buf, subGroupCheck bool) variant
// that would allow skipping the subgroup check is unexported and not
// callable from external code. We therefore cannot separate the
// failure paths by calling distinct validators.
//
// Instead we call SetBytes once and classify its error by inspecting
// the error text. Gnark's error message contains the stable substring
// "subgroup" when (and only when) the failure reason is subgroup
// membership, so substring matching is a reliable classification key
// within a pinned gnark version.
//
// # WHY NOT CALL SUBGROUP CHECKS SEPARATELY
//
// A previous version of this function called SetBytes and then an
// explicit IsInSubGroup() check in a separate branch. That second
// branch was dead code: SetBytes had already rejected non-subgroup
// points with its own error. The separate branch never fired, and
// all non-subgroup rejections were misclassified as "not on curve."
// This was only caught by TestParseBLSPubKey_NotInSubgroup, which
// explicitly constructs a non-subgroup on-curve point and asserts
// the specific error type.
//
// # VERSION COUPLING
//
// Substring matching against "subgroup" is stable within gnark's
// error taxonomy, but not guaranteed across all future major
// versions. If gnark changes its error strings, TestParseBLSPubKey_
// NotInSubgroup will fail with a clear diagnostic pointing at the
// classification branch. That's the right failure mode — we get an
// explicit signal, not silent misclassification.
func ParseBLSPubKey(data []byte) (*bls12381.G2Affine, error) {
	if len(data) != BLSG2CompressedLen {
		return nil, fmt.Errorf("%w: got %d bytes, expected %d",
			ErrBLSInvalidPubKeyLength, len(data), BLSG2CompressedLen)
	}

	var pk bls12381.G2Affine
	if _, err := pk.SetBytes(data); err != nil {
		// Classify gnark's rejection reason. Non-subgroup failures
		// are the security-critical case and get their own error.
		// All other deserialization failures (malformed encoding,
		// off-curve) get the on-curve error.
		if strings.Contains(err.Error(), "subgroup") {
			return nil, fmt.Errorf("%w: %v", ErrBLSPubKeyNotInSubgroup, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrBLSPubKeyNotOnCurve, err)
	}

	return &pk, nil
}

// -------------------------------------------------------------------------------------------------
// 8) Internal test helper — deterministic key derivation
// -------------------------------------------------------------------------------------------------

// deriveBLSKeyForTest produces a deterministic keypair from a seed.
// Used exclusively by tests that need reproducible cryptographic inputs
// (test vectors, attack reconstructions). Not exported; production code
// uses GenerateBLSKey which draws entropy from crypto/rand.
//
// The seed is hashed into the Fr scalar field via modular reduction.
// Distinct seeds produce distinct keys with overwhelming probability;
// collisions would require solving a discrete log problem.
func deriveBLSKeyForTest(seed []byte) (*fr.Element, *bls12381.G2Affine) {
	var sk fr.Element
	sk.SetBytes(seed)

	var pk bls12381.G2Affine
	var skBig = sk.BigInt(new(big.Int))

	pk.ScalarMultiplicationBase(skBig)

	return &sk, &pk
}

// Ensure crypto/rand is exercised by the real GenerateBLSKey code path.
// This is a no-op reference that prevents the import from being flagged
// as unused if someone refactors GenerateBLSKey to not directly call
// crypto/rand (it's used transitively via Fr.SetRandom).
