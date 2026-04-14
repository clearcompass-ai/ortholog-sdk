package escrow

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

func SplitGF256(secret []byte, M, N int) ([]Share, error) {
	if M < 1 || N < 1 || M > N || N > 255 { return nil, fmt.Errorf("invalid M=%d, N=%d", M, N) }
	if len(secret) == 0 { return nil, errors.New("secret must not be empty") }
	if len(secret) > MaxShareValueLen { return nil, fmt.Errorf("secret length %d exceeds max %d", len(secret), MaxShareValueLen) }
	shares := make([]Share, N)
	for i := 0; i < N; i++ { shares[i] = Share{FieldTag: FieldTagGF256, Index: byte(i+1), Value: make([]byte, len(secret))} }
	coeffs := make([]byte, M)
	for byteIdx := 0; byteIdx < len(secret); byteIdx++ {
		coeffs[0] = secret[byteIdx]
		if _, err := io.ReadFull(rand.Reader, coeffs[1:]); err != nil { return nil, fmt.Errorf("generating coefficients: %w", err) }
		for i := 0; i < N; i++ { shares[i].Value[byteIdx] = evalPolynomialGF256(coeffs, byte(i+1)) }
	}
	return shares, nil
}

func ReconstructGF256(shares []Share) ([]byte, error) {
	if len(shares) == 0 { return nil, errors.New("no shares provided") }
	tag := shares[0].FieldTag
	if tag != FieldTagGF256 { return nil, fmt.Errorf("unrecognized field tag 0x%02x", tag) }
	for i, s := range shares {
		if s.FieldTag != tag { return nil, fmt.Errorf("mixed field tags: share 0 has 0x%02x, share %d has 0x%02x", tag, i, s.FieldTag) }
	}
	secretLen := len(shares[0].Value)
	for i, s := range shares {
		if len(s.Value) != secretLen { return nil, fmt.Errorf("share %d has length %d, expected %d", i, len(s.Value), secretLen) }
	}
	seen := make(map[byte]bool)
	for _, s := range shares {
		if s.Index == 0 { return nil, errors.New("share index 0 is reserved") }
		if seen[s.Index] { return nil, fmt.Errorf("duplicate share index %d", s.Index) }
		seen[s.Index] = true
	}
	secret := make([]byte, secretLen)
	xs := make([]byte, len(shares))
	for i, s := range shares { xs[i] = s.Index }
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		ys := make([]byte, len(shares))
		for i, s := range shares { ys[i] = s.Value[byteIdx] }
		secret[byteIdx] = lagrangeInterpolateGF256(xs, ys, 0)
	}
	return secret, nil
}

func gf256Mul(a, b byte) byte {
	var result byte
	for b > 0 {
		if b&1 != 0 { result ^= a }
		carry := a & 0x80; a <<= 1
		if carry != 0 { a ^= 0x1B }
		b >>= 1
	}
	return result
}

func gf256Inv(a byte) byte {
	if a == 0 { return 0 }
	result := a
	for i := 0; i < 6; i++ { result = gf256Mul(result, result); result = gf256Mul(result, a) }
	result = gf256Mul(result, result)
	return result
}

func evalPolynomialGF256(coeffs []byte, x byte) byte {
	result := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- { result = gf256Mul(result, x) ^ coeffs[i] }
	return result
}

func lagrangeInterpolateGF256(xs, ys []byte, target byte) byte {
	var result byte
	for i := 0; i < len(xs); i++ {
		num := byte(1); den := byte(1)
		for j := 0; j < len(xs); j++ {
			if i == j { continue }
			num = gf256Mul(num, target^xs[j]); den = gf256Mul(den, xs[i]^xs[j])
		}
		result ^= gf256Mul(ys[i], gf256Mul(num, gf256Inv(den)))
	}
	return result
}
