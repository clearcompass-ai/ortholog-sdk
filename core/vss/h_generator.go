package vss

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// HGeneratorSeed is the canonical domain-separator string used to
// derive the second secp256k1 generator H for Pedersen commitments.
// Frozen on first publication; changing this string changes H and
// invalidates every commitment ever produced. The auditor reviews
// this constant explicitly. Must be human-readable, version-tagged,
// and unambiguously scoped to this package's purpose.
const HGeneratorSeed = "ortholog/core/vss/pedersen/h-generator/v1"

// HGeneratorMaxAttempts bounds the try-and-increment loop. With a
// uniformly random 256-bit candidate x-coordinate, the probability
// of failing to find a point on secp256k1 in a single attempt is
// just under 1/2 (roughly half of x values have a y on the curve).
// 256 attempts have failure probability < 2^-256 — i.e., the
// derivation will not exhaust the budget in any executable
// universe. The bound exists purely to defend against a corrupted
// build that produces a wedged loop.
const HGeneratorMaxAttempts = 256

// ErrHGeneratorExhausted is returned by HGenerator if the
// try-and-increment loop reaches HGeneratorMaxAttempts without
// finding a point on the curve. Reaching this state implies a
// catastrophic bug in this package or in the secp256k1 backing
// library; production callers can panic on this error.
var ErrHGeneratorExhausted = errors.New("vss: h-generator try-and-increment exhausted")

// HGeneratorDoc is the auditor-targeted derivation rationale for the
// H generator. Not used at runtime; exposed as a string constant so
// it surfaces in package documentation tools and so the audit can
// link source to spec.
//
// # Procedure
//
//	counter = 0
//	loop {
//	    digest = SHA-256(HGeneratorSeed || BE_uint32(counter))
//	    x = digest mod p     // p = secp256k1 field prime
//	    if there exists a y with (x, y) on secp256k1:
//	        choose y as the smaller of the two solutions
//	        return (x, y)
//	    counter += 1
//	}
//
// # Why try-and-increment instead of RFC 9380 hash-to-curve
//
// RFC 9380's SSWU map exists to give a constant-time, statistically-
// unbiased map from arbitrary inputs to curve points, used in
// per-message hashing protocols (BLS signatures, VOPRFs). For
// deriving one constant generator at startup, neither property
// matters: there is no timing-side-channel because the derivation
// runs once per process and is independent of secret data, and
// statistical bias on a single output is not meaningful. Try-and-
// increment is the standard NIH construction (Bitcoin's
// secp256k1_generator_h, Zcash's pedersen.go for the SaplingValue
// commitment generators) and avoids either an external dependency
// or ~200 lines of SSWU map implementation that the auditor would
// otherwise need to verify.
//
// # Security argument that log_G(H) is unknown
//
// Claim: Under the ECDLP assumption on secp256k1 and under the
// random oracle model for SHA-256, log_G(H) is uniformly distributed
// in [1, n-1] and uncomputable by any polynomial-time adversary —
// including the author of the HGeneratorSeed constant.
//
// Argument in four steps:
//
//  1. The seed "ortholog/core/vss/pedersen/h-generator/v1" is a
//     public ASCII string with no special structure. It is
//     human-readable text chosen for domain separation, not for any
//     numerical property. A malicious author who wanted H = k·G for
//     some known k would need to search for a seed such that, when
//     hashed with some counter, produces x = (k·G).x. That search
//     is a second-preimage attack on SHA-256 — assumed infeasible
//     at the 256-bit security level.
//
//  2. The try-and-increment derivation reads only the seed and the
//     counter as inputs. It never consults G's coordinates, n, or
//     any pre-existing curve point. The derivation is therefore
//     G-independent: a correlated seed choice cannot encode a
//     target discrete log.
//
//  3. Under the random oracle model for SHA-256, each candidate
//     x-coordinate is a uniformly random element of F_p (after the
//     mod-p reduction). For secp256k1, approximately half of F_p
//     elements are x-coordinates of curve points; the first
//     surviving candidate yields H. By the uniformity of the random
//     oracle, H is a uniformly random point in the secp256k1
//     subgroup.
//
//  4. Computing log_G(H) for a uniformly random H in the secp256k1
//     subgroup is the elliptic-curve discrete logarithm problem.
//     Under the standard ECDLP assumption on secp256k1, no
//     polynomial-time adversary can compute this k.
//
// Step 1 is the load-bearing one. The review discipline it imposes:
// the seed MUST be committed to git at the same time as the
// derivation code and BEFORE any golden test vector is computed
// for H. A reviewer can verify this from the git history
// (HGeneratorSeed and the frozen digest in
// TestHGenerator_FrozenSeed landed in the same commit). Any
// future seed rotation must follow the same discipline.
//
// # Versioning policy
//
// HGeneratorSeed is frozen. If a future scheme requires a different
// H, that scheme MUST publish a new constant — HGeneratorSeedV2 —
// rather than mutating this one. Mutation invalidates every
// commitment ever produced under the old seed.
const HGeneratorDoc = `try-and-increment from SHA-256(seed || counter), seed = HGeneratorSeed`

// hGenCache memoises the derived H point so callers do not pay the
// SHA-256 + curve-arithmetic cost on every invocation. The
// derivation is deterministic and cache-safe; sync.Once gives us
// race-free initialisation.
var (
	hGenOnce sync.Once
	hGenX    *big.Int
	hGenY    *big.Int
	hGenErr  error
)

// HGenerator returns the secp256k1 second generator H used by the
// Pedersen commitment construction in this package. Deterministic,
// cached after first call. The returned coordinates are big.Int
// values on the secp256k1 curve.
//
// Returns an error only if the try-and-increment loop exhausts
// HGeneratorMaxAttempts without finding a curve point. That state
// is unreachable in practice (probability < 2^-256) and indicates
// a build-time corruption; production callers may treat the error
// as fatal.
func HGenerator() (x, y *big.Int, err error) {
	hGenOnce.Do(func() {
		hGenX, hGenY, hGenErr = deriveHGenerator()
	})
	return hGenX, hGenY, hGenErr
}

// deriveHGenerator runs the try-and-increment derivation. Pulled
// out of HGenerator so tests can call it without disturbing the
// sync.Once cache.
func deriveHGenerator() (*big.Int, *big.Int, error) {
	curve := secp256k1.S256()
	p := curve.Params().P

	for counter := uint32(0); counter < HGeneratorMaxAttempts; counter++ {
		x := candidateX(counter, p)
		y, ok := liftX(x, curve)
		if !ok {
			continue
		}
		return x, y, nil
	}
	return nil, nil, ErrHGeneratorExhausted
}

// candidateX produces the candidate x-coordinate for the given
// try-and-increment counter: SHA-256(HGeneratorSeed || BE_uint32(counter))
// reduced modulo the field prime p.
func candidateX(counter uint32, p *big.Int) *big.Int {
	var ctrBytes [4]byte
	binary.BigEndian.PutUint32(ctrBytes[:], counter)

	h := sha256.New()
	h.Write([]byte(HGeneratorSeed))
	h.Write(ctrBytes[:])
	digest := h.Sum(nil)

	x := new(big.Int).SetBytes(digest)
	return x.Mod(x, p)
}

// liftX returns the smaller of the two y solutions to the curve
// equation y^2 = x^3 + 7 (mod p) at the given x, if any solution
// exists. The "smaller of two" tie-break is canonical and
// auditor-checkable; the alternative ("larger of two") would
// derive the additive inverse point, which is also a valid
// generator but would change every commitment if we flipped the
// rule later. Frozen as part of the derivation contract.
//
// Returns (y, true) when (x, y) is on the curve. Returns
// (nil, false) when no y exists for this x — that is, when the
// quadratic-residue check on x^3 + 7 fails.
func liftX(x *big.Int, curve *secp256k1.KoblitzCurve) (*big.Int, bool) {
	p := curve.Params().P

	// Compute the right-hand side of y^2 = x^3 + ax + b. For
	// secp256k1, a = 0 and b = 7, so the formula reduces to
	// y^2 = x^3 + 7 (mod p).
	x3 := new(big.Int).Exp(x, big.NewInt(3), p)
	rhs := new(big.Int).Add(x3, curve.Params().B)
	rhs.Mod(rhs, p)

	// Tonelli-Shanks via big.Int.ModSqrt. Returns nil when no
	// square root exists in F_p (i.e., when x is not the
	// x-coordinate of a curve point).
	y := new(big.Int).ModSqrt(rhs, p)
	if y == nil {
		return nil, false
	}

	// Belt-and-braces: confirm (x, y) is actually on the curve.
	// ModSqrt can produce a valid square root that, due to a bug
	// in the caller's RHS computation, isn't on the intended
	// curve. The IsOnCurve check is cheap and authoritative.
	if !curve.IsOnCurve(x, y) {
		return nil, false
	}

	// Pick the canonically smaller y. This must be deterministic
	// across machines and Go versions — y and (p - y) are both
	// valid roots; we pick the smaller one to fix a single H.
	pMinusY := new(big.Int).Sub(p, y)
	if pMinusY.Cmp(y) < 0 {
		y = pMinusY
	}
	return y, true
}
