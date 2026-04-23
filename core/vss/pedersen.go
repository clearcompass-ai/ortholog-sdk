package vss

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// SecretSize is the byte width of a Pedersen-VSS secret. Fixed at 32
// because the secret is a secp256k1 scalar (group order n is just
// under 2^256, so 32 bytes is the natural width). Larger payloads
// must be split via a symmetric key whose 32-byte material is the
// VSS secret.
const SecretSize = 32

// MinThreshold is the smallest meaningful M (quorum). Below 2 the
// scheme is degenerate: a 1-of-N split is just N copies of the
// secret, defeating threshold security entirely.
const MinThreshold = 2

// MaxShares caps N at 255. Indices are uint8 (matching crypto/escrow's
// V1 wire format), and index 0 is reserved (it would evaluate the
// polynomial at the secret), leaving 1..255 = 255 distinct shares.
const MaxShares = 255

// Errors. Every failure path of Split, Reconstruct, or Verify
// returns one of these wrapped sentinels so callers can distinguish
// structural mistakes from cryptographic verification failures.
var (
	ErrInvalidThreshold       = errors.New("vss: invalid threshold")
	ErrInvalidShareCount      = errors.New("vss: invalid share count")
	ErrSecretSize             = errors.New("vss: secret must be 32 bytes")
	ErrShareCountBelowQuorum  = errors.New("vss: share count below threshold")
	ErrDuplicateIndex         = errors.New("vss: duplicate share index")
	ErrShareIndexOutOfRange   = errors.New("vss: share index out of range")
	ErrCommitmentMismatch     = errors.New("vss: share fails commitment verification")
	ErrCommitmentHashMismatch = errors.New("vss: share commitment hash does not match published commitments")
	ErrCommitmentVectorEmpty  = errors.New("vss: commitment vector is empty")
	ErrInvalidCommitmentPoint = errors.New("vss: commitment point is not on the secp256k1 curve")
)

// Share is one Pedersen-VSS share. Carries the Shamir share value
// f(i), the blinding-polynomial value g(i), and a binding hash of
// the published commitment vector. Wire-formatting and persistence
// of shares is the caller's concern; this type is the in-memory
// contract for the primitive.
//
// Index ranges over 1..MaxShares; 0 is reserved (evaluating either
// polynomial at 0 reveals the constant term, which for the secret
// polynomial IS the secret).
//
// Value and BlindingFactor are 32-byte big-endian secp256k1 scalars
// (mod n). Both are secret material — callers SHOULD zeroise them
// after use.
type Share struct {
	Index          byte
	Value          [32]byte
	BlindingFactor [32]byte
	// CommitmentHash is SHA-256 over the canonical wire form of
	// the Commitments this share was issued under. Reconstruct
	// requires every supplied share to share the same hash AND to
	// match the supplied Commitments — this binds the share set
	// to a single dealer-published commitment vector and prevents
	// cross-split share mixing at the primitive layer.
	CommitmentHash [32]byte
}

// Commitments is the published M-element commitment vector
//
//	C_j = a_j·G + b_j·H,  j = 0..M-1
//
// where a_j are the secret-polynomial coefficients (a_0 is the
// secret) and b_j are the blinding-polynomial coefficients. G is
// secp256k1's standard generator; H is HGenerator().
//
// Points are stored as 65-byte uncompressed secp256k1 encodings
// (0x04 || X || Y). A nil or zero-length Points slice is invalid;
// every Split call returns a non-empty Points whose length equals
// the threshold.
//
// The Commitments vector reveals nothing about the secret beyond
// what M-1 shares would (Pedersen commitments are computationally
// hiding). It is safe to publish openly.
type Commitments struct {
	Points [][]byte
}

// Hash returns SHA-256 over the canonical wire form of the
// commitment vector. The wire form is:
//
//	BE_uint32(len(Points)) || Points[0] || Points[1] || ... || Points[len-1]
//
// Each Points[i] is exactly 65 bytes (uncompressed secp256k1).
// Including the length prefix prevents a swap-attack where two
// vectors of different M would otherwise hash identically when one
// is a prefix of the other.
//
// Every share's CommitmentHash field equals this value at the time
// of Split. Reconstruct re-derives this hash from the supplied
// Commitments and rejects shares whose CommitmentHash differs.
func (c Commitments) Hash() [32]byte {
	h := sha256.New()
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(c.Points)))
	h.Write(lenBytes[:])
	for _, p := range c.Points {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Threshold returns the threshold M implied by the commitment
// vector length. Returns 0 for an empty vector.
func (c Commitments) Threshold() int { return len(c.Points) }

// Split distributes a 32-byte secret into N Pedersen-VSS shares
// with reconstruction threshold M. Returns the shares plus the
// commitment vector every shareholder needs to verify them.
//
// Constraints:
//   - secret must be SecretSize bytes (32).
//   - M must be in [MinThreshold, N].
//   - N must be in [M, MaxShares].
//
// The secret is interpreted as a secp256k1 scalar (mod n). A
// secret whose integer value exceeds n is reduced mod n; this
// mirrors how 32 random bytes from a CSPRNG are typically used as
// a scalar. Callers that need exact-bytes preservation should
// derive the scalar themselves and pass a known-good value.
//
// Randomness is sourced from crypto/rand. For tests that need
// byte-reproducible output, splitWithReader is the unexported
// sibling that accepts an arbitrary io.Reader.
func Split(secret [SecretSize]byte, M, N int) ([]Share, Commitments, error) {
	return splitWithReader(secret, M, N, rand.Reader)
}

// splitWithReader is Split parameterised on the randomness source.
// Unexported: only tests (and the tests of downstream consumers
// that pin golden vectors) use this path.
//
// The reader must produce at least 16·M·33 bytes before any
// rejection-sampling draw for n exceeds its budget. In practice a
// healthy DRBG wrapped as io.Reader suffices.
func splitWithReader(secret [SecretSize]byte, M, N int, r io.Reader) ([]Share, Commitments, error) {
	if M < MinThreshold {
		return nil, Commitments{}, fmt.Errorf("%w: M=%d, minimum is %d", ErrInvalidThreshold, M, MinThreshold)
	}
	if N < M {
		return nil, Commitments{}, fmt.Errorf("%w: N=%d < M=%d", ErrInvalidShareCount, N, M)
	}
	if N > MaxShares {
		return nil, Commitments{}, fmt.Errorf("%w: N=%d > %d (uint8 index space)", ErrInvalidShareCount, N, MaxShares)
	}

	curve := secp256k1.S256()
	n := curve.Params().N
	hX, hY, err := HGenerator()
	if err != nil {
		return nil, Commitments{}, fmt.Errorf("vss/split: derive H: %w", err)
	}

	// Reduce secret mod n, reject zero.
	//
	// Rejection is application-layer, not cryptographic. Pedersen
	// hiding still holds for a zero secret: C_0 = 0·G + b_0·H = b_0·H,
	// a uniformly random curve point that reveals nothing about a_0.
	// The scheme's hiding property does not care about the secret's
	// value.
	//
	// But the downstream primitives do. A 32-byte zero secret used as
	// an AES-256 key is a trivially-known key (NIST SP 800-131A flags
	// it explicitly). A zero re-encryption scalar in Umbral PRE turns
	// every re-encryption into the identity operation, leaking the
	// original ciphertext. In every current Ortholog consumer, a zero
	// secret arriving at Split indicates a caller bug (uninitialised
	// buffer, failed HKDF, zeroise-before-use) rather than a
	// legitimate input — Split refuses it so the bug surfaces here
	// rather than silently proceeding to a degenerate key.
	a0 := new(big.Int).SetBytes(secret[:])
	a0.Mod(a0, n)
	if a0.Sign() == 0 {
		return nil, Commitments{}, fmt.Errorf("vss/split: secret reduces to zero scalar mod n")
	}

	// Sample the secret polynomial f(x) = a_0 + a_1·x + ... +
	// a_{M-1}·x^{M-1} and the blinding polynomial g(x) = b_0 +
	// b_1·x + ... + b_{M-1}·x^{M-1}. a_0 is the secret; b_0 and
	// every other coefficient is uniform random in Z_n.
	a := make([]*big.Int, M)
	b := make([]*big.Int, M)
	a[0] = a0
	for i := 0; i < M; i++ {
		if i > 0 {
			ai, err := randScalar(r, n)
			if err != nil {
				return nil, Commitments{}, fmt.Errorf("vss/split: random a_%d: %w", i, err)
			}
			a[i] = ai
		}
		bi, err := randScalar(r, n)
		if err != nil {
			return nil, Commitments{}, fmt.Errorf("vss/split: random b_%d: %w", i, err)
		}
		b[i] = bi
	}

	// Build commitments C_j = a_j·G + b_j·H for j = 0..M-1.
	commitments := Commitments{Points: make([][]byte, M)}
	for j := 0; j < M; j++ {
		ajGx, ajGy := curve.ScalarBaseMult(padScalar(a[j]))
		bjHx, bjHy := curve.ScalarMult(hX, hY, padScalar(b[j]))
		cx, cy := curve.Add(ajGx, ajGy, bjHx, bjHy)
		commitments.Points[j] = elliptic.Marshal(curve, cx, cy)
	}
	commitHash := commitments.Hash()

	// Evaluate both polynomials at i = 1..N to produce shares.
	shares := make([]Share, N)
	for i := 1; i <= N; i++ {
		x := big.NewInt(int64(i))
		fi := evalPoly(a, x, n)
		gi := evalPoly(b, x, n)
		s := Share{
			Index:          byte(i),
			CommitmentHash: commitHash,
		}
		copy(s.Value[:], padScalar(fi))
		copy(s.BlindingFactor[:], padScalar(gi))
		shares[i-1] = s
	}

	return shares, commitments, nil
}

// Verify checks one share against the published commitment vector.
// Returns nil iff the share is consistent with the commitments at
// the share's Index. Detection is local: any single shareholder
// can call Verify without coordination and detect a faulty dealer.
//
// Failure modes (each wraps the corresponding sentinel):
//   - ErrShareIndexOutOfRange: Index is 0 or > MaxShares.
//   - ErrCommitmentVectorEmpty: commitments.Points is empty.
//   - ErrCommitmentHashMismatch: share was issued under a
//     different commitment vector than the one supplied.
//   - ErrInvalidCommitmentPoint: a commitment point is not on
//     the secp256k1 curve (corrupted commitments).
//   - ErrCommitmentMismatch: the share's (Value, BlindingFactor)
//     does not satisfy the commitment equation. This is the
//     "dealer cheated" or "share corrupted" outcome.
func Verify(share Share, commitments Commitments) error {
	if share.Index == 0 || share.Index > MaxShares {
		return fmt.Errorf("%w: %d", ErrShareIndexOutOfRange, share.Index)
	}
	if len(commitments.Points) == 0 {
		return ErrCommitmentVectorEmpty
	}
	if commitments.Hash() != share.CommitmentHash {
		return ErrCommitmentHashMismatch
	}

	curve := secp256k1.S256()
	n := curve.Params().N
	hX, hY, err := HGenerator()
	if err != nil {
		return fmt.Errorf("vss/verify: derive H: %w", err)
	}

	// Normalise scalars mod n before any group operation.
	//
	// ScalarBaseMult / ScalarMult in both crypto/elliptic and the
	// decred/secp256k1/v4 adaptor document internal mod-n reduction,
	// but the contract across future Go versions and swap-compatible
	// curve backends is not guaranteed. A hostile caller could also
	// construct a Share whose 32-byte Value encodes an integer >= n
	// (it is not the dealer who writes the share's bytes at rest;
	// the wire form is exposed to storage and transport). Explicit
	// reduction converts the input to its canonical representative
	// before the curve operation — required for correctness of the
	// downstream equality check LHS == RHS, which expects both sides
	// to be computed from canonical scalars.
	val := new(big.Int).SetBytes(share.Value[:])
	val.Mod(val, n)
	blind := new(big.Int).SetBytes(share.BlindingFactor[:])
	blind.Mod(blind, n)

	// LHS = Value·G + BlindingFactor·H.
	lhsGx, lhsGy := curve.ScalarBaseMult(padScalar(val))
	lhsHx, lhsHy := curve.ScalarMult(hX, hY, padScalar(blind))
	lhsX, lhsY := curve.Add(lhsGx, lhsGy, lhsHx, lhsHy)

	rhsX, rhsY, err := commitmentCombine(curve, share.Index, commitments)
	if err != nil {
		return err
	}

	if lhsX.Cmp(rhsX) != 0 || lhsY.Cmp(rhsY) != 0 {
		return ErrCommitmentMismatch
	}
	return nil
}

// VerifyPoints is the point-level sibling of Verify for callers that
// have already committed to a (VK, BK) point pair rather than to the
// underlying scalars. Phase C uses this: a CFrag verifier sees the
// proxy's VK_i = G^{rk_i} and BK_i = H^{b_i} as points on the wire
// but never sees the scalars rk_i and b_i (the scalars are the
// proxy's secret).
//
// Checks (index in 1..MaxShares, non-empty commitments, non-nil
// point inputs, on-curve for vk and bk):
//
//	VK_i + BK_i  ==  sum_{j=0}^{M-1} (i^j mod n) · C_j
//
// where all points are on secp256k1. Returns nil on match, one of
// the ErrInvalid*/ErrCommitment* sentinels otherwise.
//
// # Caller contract
//
// The commitments argument MUST be the commitment vector published
// on-log under the SplitID corresponding to this CFrag's grant
// context. VerifyPoints does NOT validate that binding: it does not
// check CommitmentHash (there is no hash on the CFrag; the binding
// is enforced by the SplitID lookup, not by a hash field). Passing
// a commitment vector from a different SplitID will surface as
// ErrCommitmentMismatch — the polynomial equation will not balance —
// but the specific error will not distinguish "wrong commitments"
// from "CFrag tampered with". That discrimination happens upstream
// at the log-lookup step.
//
// Point inputs vkX, vkY, bkX, bkY must be non-nil. On-curve is
// validated here (cofactor = 1 on secp256k1, so on-curve implies
// prime-order-subgroup; no separate subgroup check is needed). A
// caller parsing points from wire bytes should still Unmarshal +
// IsOnCurve-check at ingress, so a bad wire format surfaces as a
// parse error rather than reaching this function.
//
// # Example CFrag verification flow (Phase C, crypto/artifact/pre.go)
//
//	// 1. Derive SplitID from the public grant context. ADR-005 §6.2
//	//    makes this deterministic from (grantor, recipient, artifact).
//	splitID := computePREGrantSplitID(grantorDID, recipientDID, artifactCID)
//
//	// 2. Fetch the pre-grant-commitment-v1 entry from the log.
//	entry, err := fetcher.FetchBySplitID(splitID)
//	if err != nil { return err }
//	commitments, err := extractCommitmentsFromPayload(entry.Payload)
//	if err != nil { return err }
//
//	// 3. Parse the CFrag points and on-curve-check at ingress
//	//    (not this function's concern; done by the CFrag parser).
//
//	// 4. Verify polynomial consistency — this function.
//	if err := vss.VerifyPoints(
//	    cfrag.Index, cfrag.VKX, cfrag.VKY, cfrag.BKX, cfrag.BKY,
//	    commitments,
//	); err != nil {
//	    return fmt.Errorf("CFrag polynomial check: %w", err)
//	}
//
//	// 5. Verify the DLEQ proof separately. Not this function's
//	//    concern; lives in crypto/artifact/pre.go.
//	if err := verifyDLEQ(cfrag, commitments); err != nil {
//	    return fmt.Errorf("CFrag DLEQ check: %w", err)
//	}
//
// Both step 4 and step 5 MUST pass independently. Either failing is
// a rejection: Pedersen soundness does not imply DLEQ soundness and
// vice versa.
func VerifyPoints(index byte, vkX, vkY, bkX, bkY *big.Int, commitments Commitments) error {
	if index == 0 || index > MaxShares {
		return fmt.Errorf("%w: %d", ErrShareIndexOutOfRange, index)
	}
	if len(commitments.Points) == 0 {
		return ErrCommitmentVectorEmpty
	}
	if vkX == nil || vkY == nil || bkX == nil || bkY == nil {
		return ErrCommitmentMismatch
	}

	curve := secp256k1.S256()

	// Belt-and-braces on-curve check. A caller that passes an
	// off-curve point would cause undefined behaviour in curve.Add.
	//
	// On-curve alone is sufficient on secp256k1: the curve has
	// cofactor 1, so every on-curve point is in the prime-order
	// subgroup. No separate subgroup-membership check is needed —
	// a distinct concern from BLS12-381's G2, where cofactor > 1
	// and subgroup membership is non-trivial (see the BLS signer's
	// public-key validation for the contrasting case).
	if !curve.IsOnCurve(vkX, vkY) {
		return fmt.Errorf("%w: vk", ErrInvalidCommitmentPoint)
	}
	if !curve.IsOnCurve(bkX, bkY) {
		return fmt.Errorf("%w: bk", ErrInvalidCommitmentPoint)
	}

	// LHS = VK + BK.
	lhsX, lhsY := curve.Add(vkX, vkY, bkX, bkY)

	rhsX, rhsY, err := commitmentCombine(curve, index, commitments)
	if err != nil {
		return err
	}

	if lhsX.Cmp(rhsX) != 0 || lhsY.Cmp(rhsY) != 0 {
		return ErrCommitmentMismatch
	}
	return nil
}

// commitmentCombine evaluates sum_{j=0}^{M-1} (i^j mod n) · C_j on
// the curve. Shared between Verify (scalar-side) and VerifyPoints
// (point-side). Returns the combined point or one of the
// ErrInvalidCommitmentPoint / ErrCommitmentVectorEmpty sentinels.
//
// Every commitment point is Unmarshal'd and on-curve-checked before
// use. On-curve alone suffices on secp256k1: cofactor is 1, so every
// on-curve point is in the prime-order subgroup. No separate
// subgroup-membership check is necessary.
func commitmentCombine(curve *secp256k1.KoblitzCurve, index byte, commitments Commitments) (*big.Int, *big.Int, error) {
	if len(commitments.Points) == 0 {
		return nil, nil, ErrCommitmentVectorEmpty
	}
	// Compute i^j incrementally mod n.
	n := curve.Params().N
	power := big.NewInt(1)
	idx := big.NewInt(int64(index))
	var rhsX, rhsY *big.Int
	for j, pt := range commitments.Points {
		cx, cy := elliptic.Unmarshal(curve, pt)
		if cx == nil {
			return nil, nil, fmt.Errorf("%w: point %d", ErrInvalidCommitmentPoint, j)
		}
		if !curve.IsOnCurve(cx, cy) {
			return nil, nil, fmt.Errorf("%w: point %d", ErrInvalidCommitmentPoint, j)
		}
		termX, termY := curve.ScalarMult(cx, cy, padScalar(new(big.Int).Set(power)))
		if rhsX == nil {
			rhsX, rhsY = termX, termY
		} else {
			rhsX, rhsY = curve.Add(rhsX, rhsY, termX, termY)
		}
		power.Mul(power, idx)
		power.Mod(power, n)
	}
	return rhsX, rhsY, nil
}

// Reconstruct recovers the secret from M-or-more Pedersen-VSS
// shares. Validates each share against the supplied commitments
// before doing any reconstruction work — a faulty share is
// rejected immediately, identified by its Index.
//
// The supplied Commitments MUST be the same vector the dealer
// published when constructing the shares. If shares from two
// different splits are mixed, the per-share CommitmentHash check
// inside Verify catches it before the Lagrange interpolation
// proceeds.
//
// Returns the reconstructed 32-byte secret. Callers SHOULD zeroise
// it after use.
func Reconstruct(shares []Share, commitments Commitments) ([SecretSize]byte, error) {
	var zero [SecretSize]byte
	if len(commitments.Points) == 0 {
		return zero, ErrCommitmentVectorEmpty
	}
	threshold := len(commitments.Points)
	if len(shares) < threshold {
		return zero, fmt.Errorf("%w: have %d, need %d", ErrShareCountBelowQuorum, len(shares), threshold)
	}

	// Per-share verification + duplicate-index detection.
	seen := make(map[byte]bool, len(shares))
	for i, s := range shares {
		if err := Verify(s, commitments); err != nil {
			return zero, fmt.Errorf("vss/reconstruct: share at slot %d (index %d): %w", i, s.Index, err)
		}
		if seen[s.Index] {
			return zero, fmt.Errorf("%w: %d", ErrDuplicateIndex, s.Index)
		}
		seen[s.Index] = true
	}

	curve := secp256k1.S256()
	n := curve.Params().N

	// Trim to threshold — we only need M shares for Lagrange and
	// using more does not improve correctness.
	subset := shares[:threshold]
	xs := make([]*big.Int, threshold)
	ys := make([]*big.Int, threshold)
	for i, s := range subset {
		xs[i] = big.NewInt(int64(s.Index))
		// Reduce the raw 32-byte value into its canonical scalar
		// representative mod n. Verify (above) normalises before the
		// curve check, so any bit-pattern that survives Verify
		// equals its canonical form mod n on the curve — but Lagrange
		// interpolation here is in Z_n and expects canonical inputs.
		// Reducing once before the inner loops keeps every term of
		// the interpolation in [0, n).
		yi := new(big.Int).SetBytes(s.Value[:])
		yi.Mod(yi, n)
		ys[i] = yi
	}

	// Lagrange interpolation at x = 0 in Z_n.
	secret := big.NewInt(0)
	for i := 0; i < threshold; i++ {
		// Build numerator = prod_{j != i} (-x_j)  and
		//       denominator = prod_{j != i} (x_i - x_j), both mod n.
		num := big.NewInt(1)
		den := big.NewInt(1)
		for j := 0; j < threshold; j++ {
			if i == j {
				continue
			}
			negXj := new(big.Int).Neg(xs[j])
			negXj.Mod(negXj, n)
			num.Mul(num, negXj)
			num.Mod(num, n)

			diff := new(big.Int).Sub(xs[i], xs[j])
			diff.Mod(diff, n)
			den.Mul(den, diff)
			den.Mod(den, n)
		}
		denInv := new(big.Int).ModInverse(den, n)
		if denInv == nil {
			return zero, fmt.Errorf("vss/reconstruct: degenerate share set (denominator non-invertible at slot %d)", i)
		}
		lambda := new(big.Int).Mul(num, denInv)
		lambda.Mod(lambda, n)

		term := new(big.Int).Mul(ys[i], lambda)
		term.Mod(term, n)
		secret.Add(secret, term)
		secret.Mod(secret, n)
	}

	var out [SecretSize]byte
	copy(out[:], padScalar(secret))
	return out, nil
}

// ─────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────

// padScalar returns a 32-byte big-endian encoding of x. big.Int.Bytes
// strips leading zeros, which would feed ScalarMult / ScalarBaseMult
// a different number of bytes for ~1/256 of values and produce
// undefined behaviour. Always pad.
func padScalar(x *big.Int) []byte {
	b := x.Bytes()
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// randScalar samples a uniform scalar in [1, n-1]. Refuses zero
// (zero is a degenerate coefficient: a polynomial whose top-degree
// coefficient is zero has effective degree M-2, which would let
// M-1 shares reconstruct the secret).
//
// The retry budget is a defense-in-depth bound against a pathological
// io.Reader, not a statistical necessity: with a healthy CSPRNG the
// probability of observing zero on a single draw is 1/n ≈ 2^-256, so
// any finite budget is effectively infinite. 256 is chosen as a round
// number with plenty of headroom — large enough that a budget-exhausted
// error unambiguously signals a broken reader (all tests must succeed
// on the first draw), small enough to bound the worst case to a trivial
// number of SHA-256 invocations.
func randScalar(r io.Reader, n *big.Int) (*big.Int, error) {
	const retries = 256
	for attempt := 0; attempt < retries; attempt++ {
		// rand.Int returns [0, n). We then reject zero.
		k, err := rand.Int(r, n)
		if err != nil {
			return nil, err
		}
		if k.Sign() != 0 {
			return k, nil
		}
	}
	// If the loop exits without returning a non-zero draw, the
	// reader is broken. Never reachable with a healthy CSPRNG.
	return nil, errors.New("vss: rand reader exhausted retry budget returning zero (CSPRNG broken)")
}

// evalPoly evaluates polynomial coeffs[0] + coeffs[1]*x + ... +
// coeffs[M-1]*x^(M-1) at the given x, mod n. Horner's method
// for one fewer multiplication per term.
func evalPoly(coeffs []*big.Int, x, n *big.Int) *big.Int {
	if len(coeffs) == 0 {
		return big.NewInt(0)
	}
	result := new(big.Int).Set(coeffs[len(coeffs)-1])
	for j := len(coeffs) - 2; j >= 0; j-- {
		result.Mul(result, x)
		result.Mod(result, n)
		result.Add(result, coeffs[j])
		result.Mod(result, n)
	}
	return result
}
