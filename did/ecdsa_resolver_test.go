package did_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/mr-tron/base58"
)

// ─────────────────────────────────────────────────────────────────────
// secp256k1 path
// ─────────────────────────────────────────────────────────────────────

func TestECDSAResolver_Secp256k1_RoundTrip(t *testing.T) {
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	r := did.NewECDSAKeyResolver()
	pub, err := r.ResolvePublicKey(context.Background(), kp.DID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Prove the resolved key actually verifies a signature from the
	// original private key — this catches a curve mismatch that a
	// shallow X/Y compare would miss.
	digest := sha256.Sum256([]byte("hello"))
	sig, err := signatures.SignEntry(digest, kp.PrivateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := signatures.VerifyEntry(digest, sig, pub); err != nil {
		t.Fatalf("VerifyEntry against resolved key: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// P-256 path
// ─────────────────────────────────────────────────────────────────────

func TestECDSAResolver_P256_RoundTrip(t *testing.T) {
	kp, err := did.GenerateDIDKeyP256()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	r := did.NewECDSAKeyResolver()
	pub, err := r.ResolvePublicKey(context.Background(), kp.DID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if pub.Curve.Params().Name != "P-256" {
		t.Fatalf("expected curve P-256, got %s", pub.Curve.Params().Name)
	}
	if pub.X.Cmp(kp.PrivateKey.PublicKey.X) != 0 || pub.Y.Cmp(kp.PrivateKey.PublicKey.Y) != 0 {
		t.Fatalf("resolved P-256 point != original")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Ed25519 rejection
// ─────────────────────────────────────────────────────────────────────

func TestECDSAResolver_Ed25519Rejected(t *testing.T) {
	kp, err := did.GenerateDIDKeyEd25519()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	r := did.NewECDSAKeyResolver()
	_, err = r.ResolvePublicKey(context.Background(), kp.DID)
	if !errors.Is(err, did.ErrEd25519NotECDSA) {
		t.Fatalf("got %v, want ErrEd25519NotECDSA", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// ParseDIDKey error propagation
// ─────────────────────────────────────────────────────────────────────

func TestECDSAResolver_MalformedDID(t *testing.T) {
	r := did.NewECDSAKeyResolver()
	_, err := r.ResolvePublicKey(context.Background(), "not-a-did")
	if !errors.Is(err, did.ErrInvalidDIDKey) {
		t.Fatalf("got %v, want ErrInvalidDIDKey", err)
	}
}

func TestECDSAResolver_UnsupportedMulticodec(t *testing.T) {
	// Build a did:key:z... whose multicodec prefix is not in the
	// supported set. base58btc-encode (0xff 0xff) || 32 zero bytes.
	payload := append([]byte{0xff, 0xff}, make([]byte, 32)...)
	bad := "did:key:z" + base58.Encode(payload)
	r := did.NewECDSAKeyResolver()
	_, err := r.ResolvePublicKey(context.Background(), bad)
	if !errors.Is(err, did.ErrUnsupportedMulticodec) {
		t.Fatalf("got %v, want ErrUnsupportedMulticodec", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// P-256 not-on-curve
// ─────────────────────────────────────────────────────────────────────

func TestECDSAResolver_P256NotOnCurve(t *testing.T) {
	// P-256 multicodec 0x12 0x00 followed by 33 bytes that are NOT
	// a valid compressed P-256 point: 0x02 prefix + 32 bytes of 0xff
	// (x = 2^256 - 1 is > p, so even if we pretended this were a
	// compressed point, it cannot lie on the curve).
	body := append([]byte{0x02}, make([]byte, 32)...)
	for i := 1; i < len(body); i++ {
		body[i] = 0xff
	}
	payload := append([]byte{0x12, 0x00}, body...)
	bad := "did:key:z" + base58.Encode(payload)
	r := did.NewECDSAKeyResolver()
	_, err := r.ResolvePublicKey(context.Background(), bad)
	if !errors.Is(err, did.ErrP256NotOnCurve) {
		t.Fatalf("got %v, want ErrP256NotOnCurve", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Cancelled context — must NOT short-circuit (resolution is local)
// ─────────────────────────────────────────────────────────────────────

func TestECDSAResolver_CancelledCtxIgnored(t *testing.T) {
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := did.NewECDSAKeyResolver()
	if _, err := r.ResolvePublicKey(ctx, kp.DID); err != nil {
		t.Fatalf("resolve under cancelled ctx (no IO, must succeed): %v", err)
	}
}
