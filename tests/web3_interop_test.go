/*
FILE PATH:
    tests/web3_interop_test.go

DESCRIPTION:
    Cross-implementation compatibility vectors. Every fixture in
    tests/fixtures/web3-interop.json was produced by an independent web3
    library (ethers.js v6 or viem). This file verifies that the Ortholog
    SDK's digest construction and signature verification accept those
    fixtures byte-for-byte.

KEY ARCHITECTURAL DECISIONS:
  - Fixtures are committed static JSON. The Node.js generator under
    tests/fixtures/generate-web3-fixtures.mjs is a one-time developer tool,
    NOT a CI dependency. CI needs only Go.
  - If these tests fail, your EIP-712 or EIP-191 implementation has
    diverged from the canonical JS libraries — wallets will not accept
    your signatures. The fix is in your Go code, not in the fixtures.
  - The fixture format is intentionally flat JSON with explicit hex
    strings. No base64, no length prefixes, no nested structure. A human
    can verify any record against ethers/viem with copy-paste.
*/
package tests

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// -------------------------------------------------------------------------------------------------
// 1) Fixture schema
// -------------------------------------------------------------------------------------------------

// interopFixture is one record of (private key → expected digest → expected
// signature) produced by an external web3 library. All byte fields are lower-
// case hex without 0x prefix.
type interopFixture struct {
	Source        string `json:"source"`        // "ethers-v6" | "viem"
	Name          string `json:"name"`          // human-readable test case
	PrivKeyHex    string `json:"priv_key_hex"`  // 32 bytes
	AddressHex    string `json:"address_hex"`   // 20 bytes derived from priv
	CanonicalHex  string `json:"canonical_hex"` // 32 bytes
	EIP191Digest  string `json:"eip191_digest"` // 32 bytes expected digest
	EIP191Sig     string `json:"eip191_sig"`    // 65 bytes r || s || v
	EIP712Digest  string `json:"eip712_digest"` // 32 bytes expected digest
	EIP712Sig     string `json:"eip712_sig"`    // 65 bytes r || s || v
}

type interopFile struct {
	// Frozen domain the fixtures were produced against. MUST match the
	// Ortholog EIP-712 domain or the fixtures are incoherent.
	Domain struct {
		Name              string `json:"name"`
		Version           string `json:"version"`
		ChainID           uint64 `json:"chain_id"`
		VerifyingContract string `json:"verifying_contract"`
		SaltHex           string `json:"salt_hex"`
	} `json:"domain"`
	Fixtures []interopFixture `json:"fixtures"`
}

// -------------------------------------------------------------------------------------------------
// 2) Fixture loading
// -------------------------------------------------------------------------------------------------

func loadInteropFixtures(t *testing.T) *interopFile {
	t.Helper()
	path := filepath.Join("fixtures", "web3-interop.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var f interopFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	if len(f.Fixtures) == 0 {
		t.Fatal("no fixtures loaded — interop suite would be silently vacuous")
	}
	return &f
}

// -------------------------------------------------------------------------------------------------
// 3) Domain coherence
// -------------------------------------------------------------------------------------------------

// TestInterop_DomainCoherence asserts the fixture domain matches the Go
// protocol constants. If these drift apart, the fixtures were produced
// against a different protocol and no fixture-level verification is valid.
func TestInterop_DomainCoherence(t *testing.T) {
	f := loadInteropFixtures(t)
	if f.Domain.Name != signatures.EIP712DomainName {
		t.Fatalf("fixture domain name %q != SDK %q", f.Domain.Name, signatures.EIP712DomainName)
	}
	if f.Domain.Version != signatures.EIP712DomainVersion {
		t.Fatalf("fixture domain version %q != SDK %q", f.Domain.Version, signatures.EIP712DomainVersion)
	}
	if f.Domain.ChainID != signatures.EIP712DomainChainID {
		t.Fatalf("fixture chainID %d != SDK %d", f.Domain.ChainID, signatures.EIP712DomainChainID)
	}
	saltWant := signatures.EIP712ProtocolSalt()
	saltGot := mustHex32(t, f.Domain.SaltHex)
	if saltGot != saltWant {
		t.Fatalf("fixture salt %x != SDK %x", saltGot, saltWant)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) Digest reproduction
// -------------------------------------------------------------------------------------------------

// TestInterop_EIP712Digest_MatchesExternal locks digest parity with ethers/viem.
// Any drift here means your EIP-712 construction is wrong and wallets will
// produce signatures over a different digest than you verify against.
func TestInterop_EIP712Digest_MatchesExternal(t *testing.T) {
	f := loadInteropFixtures(t)
	for _, fx := range f.Fixtures {
		t.Run(fx.Source+"/"+fx.Name, func(t *testing.T) {
			canonical := mustHex32(t, fx.CanonicalHex)
			got := signatures.EntrySigningDigest(canonical)
			want := mustHex32(t, fx.EIP712Digest)
			if got != want {
				t.Fatalf("EIP-712 digest drift from %s\ninput: %x\nwant: %x\ngot:   %x",
					fx.Source, canonical, want, got)
			}
		})
	}
}

func TestInterop_EIP191Digest_MatchesExternal(t *testing.T) {
	f := loadInteropFixtures(t)
	for _, fx := range f.Fixtures {
		t.Run(fx.Source+"/"+fx.Name, func(t *testing.T) {
			canonical, err := hex.DecodeString(fx.CanonicalHex)
			if err != nil {
				t.Fatalf("canonical hex: %v", err)
			}
			got := signatures.EIP191Digest(canonical)
			want := mustHex32(t, fx.EIP191Digest)
			if got != want {
				t.Fatalf("EIP-191 digest drift from %s\ninput: %x\nwant: %x\ngot:   %x",
					fx.Source, canonical, want, got)
			}
		})
	}
}

// -------------------------------------------------------------------------------------------------
// 5) Signature verification — external signer, Ortholog verifier
// -------------------------------------------------------------------------------------------------

// TestInterop_VerifyExternalEIP712 locks the full verification path against
// signatures produced by an external library. If these pass, a user with
// MetaMask / Rainbow / Ledger / a Coinbase Wallet can sign an Ortholog entry
// and have it verify.
func TestInterop_VerifyExternalEIP712(t *testing.T) {
	f := loadInteropFixtures(t)
	registry := did.DefaultVerifierRegistry(panicResolver{t: t})

	for _, fx := range f.Fixtures {
		t.Run(fx.Source+"/"+fx.Name, func(t *testing.T) {
			canonical := mustHex32(t, fx.CanonicalHex)
			sig := mustHex(t, fx.EIP712Sig)
			didStr := "did:pkh:eip155:1:0x" + fx.AddressHex

			if err := registry.Verify(didStr, canonical[:], sig, envelope.SigAlgoEIP712); err != nil {
				t.Fatalf("failed to verify %s signature: %v", fx.Source, err)
			}
		})
	}
}

func TestInterop_VerifyExternalEIP191(t *testing.T) {
	f := loadInteropFixtures(t)
	registry := did.DefaultVerifierRegistry(panicResolver{t: t})

	for _, fx := range f.Fixtures {
		t.Run(fx.Source+"/"+fx.Name, func(t *testing.T) {
			canonical := mustHex32(t, fx.CanonicalHex)
			sig := mustHex(t, fx.EIP191Sig)
			didStr := "did:pkh:eip155:1:0x" + fx.AddressHex

			if err := registry.Verify(didStr, canonical[:], sig, envelope.SigAlgoEIP191); err != nil {
				t.Fatalf("failed to verify %s signature: %v", fx.Source, err)
			}
		})
	}
}

// -------------------------------------------------------------------------------------------------
// 6) Defense-in-depth — reject mutated signatures
// -------------------------------------------------------------------------------------------------

// TestInterop_BitFlipRejection flips one bit in each signature byte and
// asserts verification fails. Protects against accidentally-permissive
// verifiers that would accept near-miss signatures.
func TestInterop_BitFlipRejection(t *testing.T) {
	f := loadInteropFixtures(t)
	if len(f.Fixtures) == 0 {
		t.Skip("no fixtures")
	}
	registry := did.DefaultVerifierRegistry(panicResolver{t: t})
	fx := f.Fixtures[0]
	canonical := mustHex32(t, fx.CanonicalHex)
	origSig := mustHex(t, fx.EIP712Sig)
	didStr := "did:pkh:eip155:1:0x" + fx.AddressHex

	// Flip every single bit in the signature, re-verify. Every one should fail.
	for byteIdx := 0; byteIdx < len(origSig); byteIdx++ {
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			mutated := make([]byte, len(origSig))
			copy(mutated, origSig)
			mutated[byteIdx] ^= 1 << bitIdx
			err := registry.Verify(didStr, canonical[:], mutated, envelope.SigAlgoEIP712)
			if err == nil {
				t.Fatalf("mutated sig (byte %d bit %d) verified — verifier is too permissive",
					byteIdx, bitIdx)
			}
			// Expected: either address mismatch (if the mutation changed v or r/s)
			// or an invalid-recovery-id error (if it produced an invalid v).
			if !errors.Is(err, signatures.ErrAddressMismatch) &&
				!errors.Is(err, signatures.ErrInvalidRecoveryID) &&
				!errors.Is(err, signatures.ErrInvalidSignatureLength) {
				// We don't demand a specific error — any non-nil error is fine.
				// But log unusual ones so they're visible in -v output.
				t.Logf("byte %d bit %d: %v", byteIdx, bitIdx, err)
			}
		}
	}
}
