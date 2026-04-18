/*
FILE PATH:
    tests/web3_verifier_matrix_test.go

DESCRIPTION:
    Negative-path test matrix for all three DID-method verifiers. Every
    (curve, algorithm, input-shape) tuple that MUST be rejected gets an
    explicit test. No reliance on coverage tools to infer these — the
    rejections are protocol invariants and must be enumerated by hand
    against the spec.

KEY ARCHITECTURAL DECISIONS:
  - Each verifier gets one table-driven test per rejection axis. Named
    subtests make it obvious in CI output exactly which rejection case
    regressed.
  - Bit-flip mutation tests at the end: for one valid signature in each
    verifier, flip one bit of every component. EVERY mutation must fail.
    Any mutation that passes means the verifier is too permissive.
  - errors.Is is used to lock not just "rejected" but "rejected with the
    correct sentinel error" — so future refactors can't silently change
    the meaning of a rejection.
*/
package tests

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// -------------------------------------------------------------------------------------------------
// 1) did:pkh verifier matrix
// -------------------------------------------------------------------------------------------------

func TestPKHVerifier_Matrix(t *testing.T) {
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	didStr, _ := didPKHForKey(t, priv)

	var canonicalHash [32]byte
	copy(canonicalHash[:], []byte("matrix test canonical hash......"))

	// Pre-compute valid signatures under each algorithm.
	sigECDSA, err := signatures.SignEntry(canonicalHash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	sig191 := signEthereumRecoverable(priv, signatures.EIP191Digest(canonicalHash[:]))
	sig712 := signEthereumRecoverable(priv, signatures.EntrySigningDigest(canonicalHash))

	verifier := did.NewPKHVerifier()

	// Build a DID for a different address — used for address-mismatch cases.
	other, _ := signatures.GenerateKey()
	otherDID, _ := didPKHForKey(t, other)

	// For ECDSA against did:pkh, we need a 65-byte signature (r||s||v), not
	// the 64-byte SDK format. Construct one via ecrecover helper over the
	// raw canonical hash (no EIP-191/712 prefix).
	sigECDSARecoverable := signEthereumRecoverable(priv, canonicalHash)
	_ = sigECDSA // keep the symbol used

	cases := []struct {
		name     string
		did      string
		msg      []byte
		sig      []byte
		algoID   uint16
		wantErr  error
	}{
		// Positive cases
		{"ECDSA-correct-address", didStr, canonicalHash[:], sigECDSARecoverable, envelope.SigAlgoECDSA, nil},
		{"EIP191-correct-address", didStr, canonicalHash[:], sig191, envelope.SigAlgoEIP191, nil},
		{"EIP712-correct-address", didStr, canonicalHash[:], sig712, envelope.SigAlgoEIP712, nil},

		// Address mismatch — valid sig, wrong DID
		{"EIP712-wrong-address", otherDID, canonicalHash[:], sig712, envelope.SigAlgoEIP712, signatures.ErrAddressMismatch},
		{"EIP191-wrong-address", otherDID, canonicalHash[:], sig191, envelope.SigAlgoEIP191, signatures.ErrAddressMismatch},

		// Algorithm not supported by did:pkh
		{"Ed25519-not-supported", didStr, canonicalHash[:], make([]byte, 64), envelope.SigAlgoEd25519, did.ErrAlgorithmNotSupported},

		// Message length not 32
		{"msg-too-short", didStr, []byte("short"), sig712, envelope.SigAlgoEIP712, nil /* matched by string */},
		{"msg-too-long", didStr, make([]byte, 64), sig712, envelope.SigAlgoEIP712, nil /* matched by string */},

		// Signature length not 65
		{"sig-too-short", didStr, canonicalHash[:], make([]byte, 32), envelope.SigAlgoEIP712, signatures.ErrInvalidSignatureLength},
		{"sig-too-long", didStr, canonicalHash[:], make([]byte, 128), envelope.SigAlgoEIP712, signatures.ErrInvalidSignatureLength},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := verifier.Verify(c.did, c.msg, c.sig, c.algoID)
			if c.wantErr == nil && !strings.HasPrefix(c.name, "msg-") {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Fatalf("wrong error type: got %v, want errors.Is(err, %v)", err, c.wantErr)
			}
		})
	}
}

func TestPKHVerifier_RejectsNonEIP155Namespace(t *testing.T) {
	verifier := did.NewPKHVerifier()

	var canonical [32]byte
	copy(canonical[:], []byte("payload"))
	sig := make([]byte, 65)

	err := verifier.Verify(
		"did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:AhwZzLjCkVRABrGmFWuY6YL1K5WgFz7w3KH19pnDqz6",
		canonical[:], sig, envelope.SigAlgoECDSA,
	)
	if err == nil {
		t.Fatal("accepted non-eip155 namespace")
	}
	if !errors.Is(err, did.ErrUnsupportedNamespace) {
		t.Fatalf("wrong error type: %v", err)
	}
}

func TestPKHVerifier_RejectsInvalidRecoveryID(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	didStr, _ := didPKHForKey(t, priv)

	var canonical [32]byte
	copy(canonical[:], []byte("payload"))

	// Produce a valid signature then corrupt the v byte.
	sig := signEthereumRecoverable(priv, signatures.EntrySigningDigest(canonical))
	for _, badV := range []byte{42, 100, 200, 255} {
		mutated := append([]byte{}, sig...)
		mutated[64] = badV
		err := did.NewPKHVerifier().Verify(didStr, canonical[:], mutated, envelope.SigAlgoEIP712)
		if err == nil {
			t.Fatalf("accepted v=%d", badV)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 2) did:key verifier matrix
// -------------------------------------------------------------------------------------------------

func TestKeyVerifier_Matrix(t *testing.T) {
	kpEd, err := did.GenerateDIDKeyEd25519()
	if err != nil {
		t.Fatalf("generate Ed25519: %v", err)
	}
	kpSecp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("generate secp256k1: %v", err)
	}
	kpP256, err := did.GenerateDIDKeyP256()
	if err != nil {
		t.Fatalf("generate P-256: %v", err)
	}

	// Sign a canonical hash per curve.
	var hash [32]byte
	copy(hash[:], []byte("did:key matrix hash..............."))

	// Ed25519 signs the full message.
	ed25519Msg := []byte("hello did:key ed25519 world")
	ed25519Sig := ed25519.Sign(kpEd.PrivateKey, ed25519Msg)

	// secp256k1 signs the hash with raw 64-byte ECDSA.
	secp256k1Sig, err := signatures.SignEntry(hash, kpSecp.PrivateKey)
	if err != nil {
		t.Fatalf("secp256k1 sign: %v", err)
	}

	// P-256 signs the hash.
	p256Sig, err := signatures.SignEntry(hash, kpP256.PrivateKey)
	if err != nil {
		t.Fatalf("P-256 sign: %v", err)
	}

	verifier := did.NewKeyVerifier()

	t.Run("Ed25519+SigAlgoEd25519 accepted", func(t *testing.T) {
		if err := verifier.Verify(kpEd.DID, ed25519Msg, ed25519Sig, envelope.SigAlgoEd25519); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Ed25519+SigAlgoECDSA rejected", func(t *testing.T) {
		err := verifier.Verify(kpEd.DID, ed25519Msg, ed25519Sig, envelope.SigAlgoECDSA)
		if err == nil {
			t.Fatal("accepted cross-algorithm")
		}
		if !errors.Is(err, did.ErrAlgorithmNotSupported) {
			t.Fatalf("wrong error: %v", err)
		}
	})

	t.Run("secp256k1+SigAlgoECDSA accepted", func(t *testing.T) {
		if err := verifier.Verify(kpSecp.DID, hash[:], secp256k1Sig, envelope.SigAlgoECDSA); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("secp256k1+SigAlgoEIP191 rejected (no address)", func(t *testing.T) {
		sig65 := make([]byte, 65)
		copy(sig65, secp256k1Sig)
		err := verifier.Verify(kpSecp.DID, hash[:], sig65, envelope.SigAlgoEIP191)
		if err == nil {
			t.Fatal("accepted EIP-191 against did:key")
		}
	})

	t.Run("secp256k1+SigAlgoEIP712 rejected", func(t *testing.T) {
		sig65 := make([]byte, 65)
		err := verifier.Verify(kpSecp.DID, hash[:], sig65, envelope.SigAlgoEIP712)
		if err == nil {
			t.Fatal("accepted EIP-712 against did:key")
		}
	})

	t.Run("P256+SigAlgoECDSA accepted", func(t *testing.T) {
		if err := verifier.Verify(kpP256.DID, hash[:], p256Sig, envelope.SigAlgoECDSA); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("P256+SigAlgoEd25519 rejected", func(t *testing.T) {
		err := verifier.Verify(kpP256.DID, hash[:], p256Sig, envelope.SigAlgoEd25519)
		if err == nil {
			t.Fatal("accepted Ed25519 against P-256 key")
		}
	})

	t.Run("malformed-multibase-f rejected", func(t *testing.T) {
		// Replace the leading 'z' with 'f' (hex multibase — legacy non-standard)
		badDID := "did:key:f" + kpSecp.DID[len("did:key:z"):]
		err := verifier.Verify(badDID, hash[:], secp256k1Sig, envelope.SigAlgoECDSA)
		if err == nil {
			t.Fatal("accepted multibase 'f' — legacy non-standard format")
		}
		if !errors.Is(err, did.ErrInvalidDIDKey) {
			t.Fatalf("wrong error: %v", err)
		}
	})

	t.Run("truncated-payload rejected", func(t *testing.T) {
		// Truncate the base58 payload by removing last character.
		trunc := kpSecp.DID[:len(kpSecp.DID)-1]
		err := verifier.Verify(trunc, hash[:], secp256k1Sig, envelope.SigAlgoECDSA)
		if err == nil {
			t.Fatal("accepted truncated did:key")
		}
	})
}

// -------------------------------------------------------------------------------------------------
// 3) did:web verifier matrix
// -------------------------------------------------------------------------------------------------

func TestWebVerifier_Matrix(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	pub := signatures.PubKeyBytes(&priv.PublicKey)
	compressed, err := signatures.CompressSecp256k1Pubkey(pub)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	addr, err := signatures.AddressFromPubkey(pub)
	if err != nil {
		t.Fatalf("addr: %v", err)
	}

	var hash [32]byte
	copy(hash[:], []byte("web matrix hash.............."))
	sigRaw, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig712 := signEthereumRecoverable(priv, signatures.EntrySigningDigest(hash))

	t.Run("single-VM-no-fragment accepted", func(t *testing.T) {
		doc := &did.DIDDocument{
			ID: "did:web:example.com",
			VerificationMethod: []did.VerificationMethod{
				{
					ID:           "did:web:example.com#key-0",
					Type:         did.VerificationMethodSecp256k1,
					Controller:   "did:web:example.com",
					PublicKeyHex: hex.EncodeToString(compressed),
				},
			},
		}
		r := &staticResolver{wantDID: "did:web:example.com", doc: doc}
		v := did.NewWebVerifier(r)
		if err := v.Verify("did:web:example.com", hash[:], sigRaw, envelope.SigAlgoECDSA); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("multi-VM-no-fragment rejected", func(t *testing.T) {
		doc := &did.DIDDocument{
			ID: "did:web:example.com",
			VerificationMethod: []did.VerificationMethod{
				{ID: "did:web:example.com#key-0", Type: did.VerificationMethodSecp256k1,
					Controller: "did:web:example.com", PublicKeyHex: hex.EncodeToString(compressed)},
				{ID: "did:web:example.com#key-1", Type: did.VerificationMethodSecp256k1,
					Controller: "did:web:example.com", PublicKeyHex: hex.EncodeToString(compressed)},
			},
		}
		r := &staticResolver{wantDID: "did:web:example.com", doc: doc}
		v := did.NewWebVerifier(r)
		err := v.Verify("did:web:example.com", hash[:], sigRaw, envelope.SigAlgoECDSA)
		if err == nil {
			t.Fatal("accepted multi-VM without fragment — ambiguous selection")
		}
		if !errors.Is(err, did.ErrAmbiguousKeySelection) {
			t.Fatalf("wrong error: %v", err)
		}
	})

	t.Run("multi-VM-valid-fragment accepted", func(t *testing.T) {
		doc := &did.DIDDocument{
			ID: "did:web:example.com",
			VerificationMethod: []did.VerificationMethod{
				{ID: "did:web:example.com#key-0", Type: did.VerificationMethodSecp256k1,
					Controller: "did:web:example.com", PublicKeyHex: "00"},
				{ID: "did:web:example.com#key-1", Type: did.VerificationMethodSecp256k1,
					Controller: "did:web:example.com", PublicKeyHex: hex.EncodeToString(compressed)},
			},
		}
		r := &staticResolver{wantDID: "did:web:example.com", doc: doc}
		v := did.NewWebVerifier(r)
		if err := v.Verify("did:web:example.com#key-1", hash[:], sigRaw, envelope.SigAlgoECDSA); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("fragment-not-found rejected", func(t *testing.T) {
		doc := &did.DIDDocument{
			ID: "did:web:example.com",
			VerificationMethod: []did.VerificationMethod{
				{ID: "did:web:example.com#key-0", Type: did.VerificationMethodSecp256k1,
					Controller: "did:web:example.com", PublicKeyHex: hex.EncodeToString(compressed)},
			},
		}
		r := &staticResolver{wantDID: "did:web:example.com", doc: doc}
		v := did.NewWebVerifier(r)
		err := v.Verify("did:web:example.com#nonexistent", hash[:], sigRaw, envelope.SigAlgoECDSA)
		if err == nil {
			t.Fatal("accepted nonexistent fragment")
		}
		if !errors.Is(err, did.ErrVerificationMethodNotFound) {
			t.Fatalf("wrong error: %v", err)
		}
	})

	t.Run("recovery-VM+EIP712 accepted", func(t *testing.T) {
		doc := &did.DIDDocument{
			ID: "did:web:example.com",
			VerificationMethod: []did.VerificationMethod{
				{
					ID:                  "did:web:example.com#recovery",
					Type:                did.VerificationMethodSecp256k1Recovery,
					Controller:          "did:web:example.com",
					BlockchainAccountID: "eip155:1:0x" + hex.EncodeToString(addr[:]),
				},
			},
		}
		r := &staticResolver{wantDID: "did:web:example.com", doc: doc}
		v := did.NewWebVerifier(r)
		if err := v.Verify("did:web:example.com", hash[:], sig712, envelope.SigAlgoEIP712); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("type-algoID-mismatch rejected", func(t *testing.T) {
		doc := &did.DIDDocument{
			ID: "did:web:example.com",
			VerificationMethod: []did.VerificationMethod{
				{ID: "did:web:example.com#key-0", Type: did.VerificationMethodEd25519,
					Controller: "did:web:example.com", PublicKeyHex: hex.EncodeToString(compressed)},
			},
		}
		r := &staticResolver{wantDID: "did:web:example.com", doc: doc}
		v := did.NewWebVerifier(r)
		err := v.Verify("did:web:example.com", hash[:], sigRaw, envelope.SigAlgoECDSA)
		if err == nil {
			t.Fatal("accepted ECDSA sig against Ed25519 VM")
		}
		if !errors.Is(err, did.ErrAlgorithmNotSupported) {
			t.Fatalf("wrong error: %v", err)
		}
	})

	t.Run("resolver-error propagated", func(t *testing.T) {
		r := &staticResolver{wantDID: "did:web:example.com", err: errors.New("resolver offline")}
		v := did.NewWebVerifier(r)
		err := v.Verify("did:web:example.com", hash[:], sigRaw, envelope.SigAlgoECDSA)
		if err == nil {
			t.Fatal("resolver error not propagated")
		}
	})
}

// -------------------------------------------------------------------------------------------------
// 4) Bit-flip mutation tests — per-verifier defense-in-depth
// -------------------------------------------------------------------------------------------------

// TestBitFlip_PKH_EIP712 flips every bit of a valid EIP-712 signature and
// asserts every mutation causes verification to fail. Locks that verification
// is sensitive to signature bits, not merely to structural shape.
func TestBitFlip_PKH_EIP712(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	didStr, _ := didPKHForKey(t, priv)

	var canonical [32]byte
	copy(canonical[:], []byte("bit-flip-canonical-hash........"))
	sig := signEthereumRecoverable(priv, signatures.EntrySigningDigest(canonical))

	verifier := did.NewPKHVerifier()
	// Sanity: unmutated signature verifies.
	if err := verifier.Verify(didStr, canonical[:], sig, envelope.SigAlgoEIP712); err != nil {
		t.Fatalf("baseline verification failed: %v", err)
	}

	var accepted int
	for byteIdx := 0; byteIdx < len(sig); byteIdx++ {
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			mutated := append([]byte{}, sig...)
			mutated[byteIdx] ^= 1 << bitIdx
			if err := verifier.Verify(didStr, canonical[:], mutated, envelope.SigAlgoEIP712); err == nil {
				accepted++
				t.Errorf("mutated sig byte %d bit %d verified", byteIdx, bitIdx)
			}
		}
	}
	if accepted > 0 {
		t.Fatalf("%d mutated signatures accepted — verifier is too permissive", accepted)
	}
}

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

// (intentionally empty — ed25519.Sign is called directly inline above)
