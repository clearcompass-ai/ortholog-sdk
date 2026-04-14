// Package escrow implements Shamir M-of-N secret sharing and blind routing.
package escrow

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// SplitGF256 splits a secret into N shares with threshold M using GF(256)
// with the AES irreducible polynomial (0x11B). All shares carry the 0x01
// field tag (Decision 48).
//
// The secret can be any length. Each byte is split independently.
// Returns N shares, each with the same length as the secret plus the
// 2-byte header (tag + index).
func SplitGF256(secret []byte, M, N int) ([]Share, error) {
	if M < 1 || N < 1 || M > N || N > 255 {
		return nil, fmt.Errorf("invalid M=%d, N=%d: require 1 <= M <= N <= 255", M, N)
	}
	if len(secret) == 0 {
		return nil, errors.New("secret must not be empty")
	}
	if len(secret) > MaxShareValueLen {
		return nil, fmt.Errorf("secret length %d exceeds max %d", len(secret), MaxShareValueLen)
	}

	shares := make([]Share, N)
	for i := 0; i < N; i++ {
		shares[i] = Share{
			FieldTag: FieldTagGF256,
			Index:    byte(i + 1), // Indices 1..N (0 is reserved for the secret)
			Value:    make([]byte, len(secret)),
		}
	}

	// For each byte of the secret, generate a random polynomial of degree M-1
	// and evaluate at points 1..N.
	coeffs := make([]byte, M)
	for byteIdx := 0; byteIdx < len(secret); byteIdx++ {
		coeffs[0] = secret[byteIdx] // Constant term = secret byte
		// Random coefficients for degrees 1..M-1
		if _, err := io.ReadFull(rand.Reader, coeffs[1:]); err != nil {
			return nil, fmt.Errorf("generating coefficients: %w", err)
		}
		for i := 0; i < N; i++ {
			x := byte(i + 1)
			shares[i].Value[byteIdx] = evalPolynomialGF256(coeffs, x)
		}
	}

	return shares, nil
}

// ReconstructGF256 reconstructs the secret from M or more shares.
// Reads the field tag from the first share, verifies all shares carry the
// same tag, and rejects the share set with an explicit error if tags are
// mixed or unrecognized. Without the tag, cross-field reconstruction produces
// a valid-looking key that silently decrypts to garbage (Decision 48).
func ReconstructGF256(shares []Share) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}

	// Validate field tags — all must match and be recognized.
	tag := shares[0].FieldTag
	if tag != FieldTagGF256 {
		return nil, fmt.Errorf("unrecognized field tag 0x%02x (expected 0x%02x for GF(256))", tag, FieldTagGF256)
	}
	for i, s := range shares {
		if s.FieldTag != tag {
			return nil, fmt.Errorf("mixed field tags: share 0 has 0x%02x, share %d has 0x%02x", tag, i, s.FieldTag)
		}
	}

	// All shares must have the same value length.
	secretLen := len(shares[0].Value)
	for i, s := range shares {
		if len(s.Value) != secretLen {
			return nil, fmt.Errorf("share %d has length %d, expected %d", i, len(s.Value), secretLen)
		}
	}

	// Check for duplicate indices.
	seen := make(map[byte]bool, len(shares))
	for _, s := range shares {
		if s.Index == 0 {
			return nil, errors.New("share index 0 is reserved")
		}
		if seen[s.Index] {
			return nil, fmt.Errorf("duplicate share index %d", s.Index)
		}
		seen[s.Index] = true
	}

	// Lagrange interpolation at x=0 for each byte position.
	secret := make([]byte, secretLen)
	xs := make([]byte, len(shares))
	for i, s := range shares {
		xs[i] = s.Index
	}

	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		ys := make([]byte, len(shares))
		for i, s := range shares {
			ys[i] = s.Value[byteIdx]
		}
		secret[byteIdx] = lagrangeInterpolateGF256(xs, ys, 0)
	}

	return secret, nil
}

// ── GF(256) arithmetic using the AES irreducible polynomial 0x11B ──────

// gf256Mul multiplies two elements in GF(256) with polynomial 0x11B.
func gf256Mul(a, b byte) byte {
	var result byte
	for b > 0 {
		if b&1 != 0 {
			result ^= a
		}
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0x1B // x^8 + x^4 + x^3 + x + 1 (low byte of 0x11B)
		}
		b >>= 1
	}
	return result
}

// gf256Inv computes the multiplicative inverse in GF(256). 0 has no inverse.
func gf256Inv(a byte) byte {
	if a == 0 {
		return 0 // Convention: inv(0) = 0 (never used on valid shares)
	}
	// Use exponentiation: a^254 = a^(-1) in GF(256) since a^255 = 1.
	result := a
	for i := 0; i < 6; i++ {
		result = gf256Mul(result, result)
		result = gf256Mul(result, a)
	}
	result = gf256Mul(result, result)
	return result
}

// evalPolynomialGF256 evaluates a polynomial at point x in GF(256).
// coeffs[0] is the constant term.
func evalPolynomialGF256(coeffs []byte, x byte) byte {
	// Horner's method.
	result := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		result = gf256Mul(result, x) ^ coeffs[i]
	}
	return result
}

// lagrangeInterpolateGF256 computes Lagrange interpolation at point target in GF(256).
func lagrangeInterpolateGF256(xs, ys []byte, target byte) byte {
	var result byte
	for i := 0; i < len(xs); i++ {
		// Compute Lagrange basis polynomial L_i(target).
		num := byte(1)
		den := byte(1)
		for j := 0; j < len(xs); j++ {
			if i == j {
				continue
			}
			num = gf256Mul(num, target^xs[j])
			den = gf256Mul(den, xs[i]^xs[j])
		}
		basis := gf256Mul(num, gf256Inv(den))
		result ^= gf256Mul(ys[i], basis)
	}
	return result
}
