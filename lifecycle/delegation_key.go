/*
Package lifecycle — delegation_key.go implements artifact-scoped delegation keys
for Umbral Proxy Re-Encryption (PRE).

THE THREAT MODEL (Collusion Key Extraction):
Scalar-multiplication PRE schemes on secp256k1 have a mathematical property where:

	rk = sk_owner * d^{-1} mod n
	d  = H(sk_recipient * pk_owner)

Because the recipient MUST be able to compute `d` to decrypt, any collusion between
the recipient and M escrow nodes (who can reconstruct `rk` via Lagrange interpolation)
allows the colluding party to trivially extract `sk_owner` (sk_owner = rk * d mod n).

THE STRUCTURAL FIX:
To neutralize this, the Master Identity Key (`sk_owner`) MUST NEVER be passed to PRE
cryptographic operations. Instead, the SDK generates a highly ephemeral "Delegation Key"
(`sk_del`, `pk_del`) scoped specifically to ONE artifact.

 1. Publish: Generates `sk_del`. Returns `pk_del` for the capsule, and an
    ECIES-wrapped `sk_del` to be persisted in the ArtifactKeyStore.
 2. Grant: The owner's HSM/enclave unwraps `sk_del`, and passes it to the
    PRE KFrag generation phase.

If a recipient and M proxies collude, they extract `sk_del`—a disposable key that
only decrypts the single artifact the recipient already had permission to access.
Zero lateral movement. The Master Identity Key remains mathematically isolated.
*/
package lifecycle

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
)

// ─────────────────────────────────────────────────────────────────────
// GenerateDelegationKey
// ─────────────────────────────────────────────────────────────────────

// GenerateDelegationKey creates a per-artifact delegation keypair
// and ECIES-wraps the private key for the owner's master public key.
//
// Called at artifact publish time. The returned pkDel goes into the
// Domain Payload (replacing pk_owner). The returned wrappedSkDel goes
// into the ArtifactKeyStore (keyed by artifact CID).
//
// The owner's master private key never touches this function.
// Only the master PUBLIC key is needed — to wrap sk_del via ECIES
// so only the master key holder can unwrap it later.
//
// Returns:
//   - pkDel: 65-byte uncompressed secp256k1 public key
//   - wrappedSkDel: ECIES ciphertext (~113 bytes)
func GenerateDelegationKey(ownerPubKey []byte) (pkDel []byte, wrappedSkDel []byte, err error) {
	// 1. Parse owner public key (uses helper from lifecycle/helpers.go)
	ownerPub, err := parseSecp256k1PubKey(ownerPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("lifecycle/delegation_key: invalid owner public key: %w", err)
	}

	// 2. Generate ephemeral secp256k1 keypair
	c := secp256k1Curve()
	delKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("lifecycle/delegation_key: generate keypair: %w", err)
	}

	// 3. Serialize delegation private key (32 bytes)
	skDelBytes := padScalarTo32(delKey.D)

	// Best-effort memory hygiene: zero out the plaintext private key slice
	// once it has been successfully wrapped.
	defer func() {
		for i := range skDelBytes {
			skDelBytes[i] = 0
		}
	}()

	// 4. Extract public key as 65-byte uncompressed point
	// (0x04 prefix + 32-byte X + 32-byte Y)
	pkDel = make([]byte, 65)
	pkDel[0] = 0x04
	copy(pkDel[1:33], padScalarTo32(delKey.PublicKey.X))
	copy(pkDel[33:65], padScalarTo32(delKey.PublicKey.Y))

	// 5. ECIES-wrap sk_del for the owner's master public key
	// Reuses escrow.EncryptForNode — same ECIES primitive, same curve.
	wrappedSkDel, err = escrow.EncryptForNode(skDelBytes, ownerPub)
	if err != nil {
		return nil, nil, fmt.Errorf("lifecycle/delegation_key: wrap delegation key: %w", err)
	}

	return pkDel, wrappedSkDel, nil
}

// ─────────────────────────────────────────────────────────────────────
// UnwrapDelegationKey
// ─────────────────────────────────────────────────────────────────────

// UnwrapDelegationKey decrypts a wrapped delegation key using the
// owner's master private key.
//
// Called at grant time, inside the exchange's HSM or enclave.
// The returned skDel is passed to GrantArtifactAccess as OwnerSecretKey.
//
// In production deployments with HSMs, the exchange may call
// HSM.ECIES_Decrypt(wrappedSkDel) internally and not use this function at all,
// as the HSM never exports the master key. This function exists for:
//
//	(1) Testing and development (in-memory keys)
//	(2) Software-only deployments without HSMs
//	(3) Documentation — showing the intended cryptographic data flow
//
// Returns:
//   - skDel: 32-byte secp256k1 private key scalar
func UnwrapDelegationKey(wrappedSkDel []byte, ownerSecretKey []byte) ([]byte, error) {
	if len(ownerSecretKey) != 32 {
		return nil, fmt.Errorf("lifecycle/delegation_key: invalid owner key length %d, expected 32", len(ownerSecretKey))
	}

	// 1. Reconstruct the owner's ecdsa.PrivateKey
	c := secp256k1Curve()
	d := new(big.Int).SetBytes(ownerSecretKey)

	// Validate the scalar is within the curve's order (1 <= d < N)
	if d.Sign() == 0 || d.Cmp(c.Params().N) >= 0 {
		return nil, errors.New("lifecycle/delegation_key: invalid owner private key scalar")
	}

	x, y := c.ScalarBaseMult(ownerSecretKey)
	ownerPriv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y},
		D:         d,
	}

	// 2. ECIES-decrypt to recover sk_del
	skDel, err := escrow.DecryptFromNode(wrappedSkDel, ownerPriv)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/delegation_key: unwrap delegation key: %w", err)
	}

	// 3. Verify recovered key length
	if len(skDel) != 32 {
		// Best-effort zeroing of the malformed key
		for i := range skDel {
			skDel[i] = 0
		}
		return nil, fmt.Errorf("lifecycle/delegation_key: unwrapped key wrong length %d, expected 32", len(skDel))
	}

	// 4. Verify the recovered scalar is in the valid curve range
	// (1 <= skDel < N). A malicious or corrupted escrow node could
	// return 32 well-formed bytes that decode to 0 or a value >= N,
	// either of which would silently corrupt every downstream
	// cryptographic operation (ORTHO-BUG-014). Mirrors the
	// ownerSecretKey range check above.
	sk := new(big.Int).SetBytes(skDel)
	if sk.Sign() == 0 || sk.Cmp(c.Params().N) >= 0 {
		for i := range skDel {
			skDel[i] = 0
		}
		return nil, errors.New("lifecycle/delegation_key: unwrapped scalar out of range [1, N)")
	}

	return skDel, nil
}

// ─────────────────────────────────────────────────────────────────────
// Internal Helpers
// ─────────────────────────────────────────────────────────────────────

// padScalarTo32 ensures a big.Int is exactly 32 bytes long, padding with
// leading zeros if necessary. Essential for deterministic secp256k1 scalars.
func padScalarTo32(b *big.Int) []byte {
	buf := b.Bytes()
	if len(buf) >= 32 {
		return buf[len(buf)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(buf):], buf)
	return padded
}
