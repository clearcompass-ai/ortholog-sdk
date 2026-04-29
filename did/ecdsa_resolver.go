/*
FILE PATH:
    did/ecdsa_resolver.go

DESCRIPTION:
    ECDSAKeyResolver — local-only resolver for did:key:... identifiers
    that returns *ecdsa.PublicKey, the shape every operator-side
    signature verifier consumes.

    Promoted from ortholog-operator/admission/didkey_resolver.go so the
    operator can drop its private adapter and import this struct
    directly. Implements the structurally-compatible interface

        type DIDResolver interface {
            ResolvePublicKey(ctx context.Context, did string) (*ecdsa.PublicKey, error)
        }

    that ortholog-operator/api/submission.go declares locally — no fat
    interface imposed across the boundary; the operator keeps its
    "accept interfaces, return structs" Go idiom intact.

KEY ARCHITECTURAL DECISIONS:
  - Named ECDSAKeyResolver rather than KeyResolver because did/key_resolver.go
    already exports a KeyResolver type whose Resolve method returns
    *DIDDocument. Renaming avoids method-set collision and makes the
    return-shape obvious from the type name.
  - Two curves only: secp256k1 (multicodec 0xe701) and P-256 (0x1200).
    Both produce *ecdsa.PublicKey. Ed25519 keys (0xed01) are EdDSA, not
    ECDSA, and would never satisfy signatures.VerifyEntry; ResolvePublicKey
    rejects them explicitly so the caller's misconfiguration surfaces
    at resolution time instead of producing a confusing signature
    mismatch downstream.
  - Stateless. Safe to share across goroutines. No network IO — did:key
    is self-contained.

WIRING (operator side):
    cmd/operator/main.go installs an instance as the default
    Identity.DIDResolver:

        deps.Identity.DIDResolver = did.NewECDSAKeyResolver()

    Operators that need richer methods (did:web, did:pkh) compose a
    multi-method resolver in main.go; this adapter remains the
    secp256k1 / P-256 leaf.

KEY DEPENDENCIES:
    - crypto/signatures.ParsePubKey: secp256k1 33-byte compressed → *ecdsa.PublicKey
    - elliptic.UnmarshalCompressed:  P-256 33-byte compressed → curve point
    - did/key_resolver.go:           ParseDIDKey + verification method constants
*/
package did

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrEd25519NotECDSA is returned when ResolvePublicKey is called with
// an Ed25519 did:key. EdDSA keys cannot satisfy *ecdsa.PublicKey;
// admission's verifier expects ECDSA. Surfacing this as a typed
// sentinel lets callers route Ed25519 to a separate verifier path
// without parsing error strings.
var ErrEd25519NotECDSA = errors.New("did/ecdsa: Ed25519 key cannot resolve to *ecdsa.PublicKey — use a separate verifier for EdDSA")

// ErrUnsupportedVerificationMethod is returned when ParseDIDKey
// dispatches to a verification method this resolver does not support.
// Currently only triggered by future curves added to ParseDIDKey
// without a matching case here.
var ErrUnsupportedVerificationMethod = errors.New("did/ecdsa: unsupported verification method")

// ErrP256NotOnCurve is returned when a did:key claims P-256 but the
// embedded compressed point fails the curve equation.
var ErrP256NotOnCurve = errors.New("did/ecdsa: P-256 unmarshal failed (point not on curve)")

// ─────────────────────────────────────────────────────────────────────
// ECDSAKeyResolver
// ─────────────────────────────────────────────────────────────────────

// ECDSAKeyResolver resolves did:key:... identifiers to *ecdsa.PublicKey
// for the secp256k1 and P-256 curves.
//
// Stateless; safe to share across goroutines. No network IO —
// did:key embeds the public key in the identifier.
type ECDSAKeyResolver struct{}

// NewECDSAKeyResolver returns a stateless ECDSA-flavored did:key
// resolver. Returned value is safe for concurrent use.
func NewECDSAKeyResolver() *ECDSAKeyResolver { return &ECDSAKeyResolver{} }

// ResolvePublicKey decodes a did:key identifier and returns the
// embedded ECDSA public key.
//
// The context is accepted for interface compatibility; resolution is
// purely local so cancellation is a no-op.
//
// Errors:
//   - ErrInvalidDIDKey / ErrUnsupportedMulticodec       (from ParseDIDKey)
//   - ErrEd25519NotECDSA                                (Ed25519 input)
//   - ErrP256NotOnCurve                                 (P-256 unmarshal)
//   - ErrUnsupportedVerificationMethod                  (future curve)
func (r *ECDSAKeyResolver) ResolvePublicKey(_ context.Context, didStr string) (*ecdsa.PublicKey, error) {
	pubBytes, vmType, err := ParseDIDKey(didStr)
	if err != nil {
		return nil, fmt.Errorf("did/ecdsa: %w", err)
	}
	switch vmType {
	case VerificationMethodSecp256k1:
		// SDK helper handles both 33-byte compressed and 65-byte
		// uncompressed forms; did:key always carries compressed.
		return signatures.ParsePubKey(pubBytes)
	case VerificationMethodP256:
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pubBytes)
		if x == nil {
			return nil, ErrP256NotOnCurve
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	case VerificationMethodEd25519:
		return nil, ErrEd25519NotECDSA
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedVerificationMethod, vmType)
	}
}
