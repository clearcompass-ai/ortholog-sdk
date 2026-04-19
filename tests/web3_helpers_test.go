/*
FILE PATH:

	tests/web3_helpers_test.go

DESCRIPTION:

	Shared test helpers for the web3 test suite. Recoverable-signature
	production for Ethereum-format sigs, did:pkh construction from a private
	key, and stub DID resolvers that fail loudly if accidentally invoked.

KEY ARCHITECTURAL DECISIONS:
  - The SDK's `signatures.SignEntry` produces 64-byte low-S ECDSA for
    SDK-native signers. Wallet-format sigs (65-byte r || s || v) require
    recovery-id computation, which the production SDK does not need and
    therefore does not expose. Tests need it to simulate wallet signatures,
    so the helper is scoped to test code only.
  - Stub resolvers panic on invocation rather than returning a nil document.
    A did:pkh / did:key verifier that accidentally touches the resolver is
    a wiring bug — silent failure masks it.
*/
package tests

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"

	decredsecp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// -------------------------------------------------------------------------------------------------
// 1) Recoverable signing (Ethereum-format 65-byte r || s || v)
// -------------------------------------------------------------------------------------------------

// signEthereumRecoverable produces a 65-byte signature in Ethereum
// wire format: [r (32 bytes)][s (32 bytes)][v (1 byte, 27 or 28)].
//
// Used by tests that must simulate wallet-produced signatures. Production
// signers pass through eth_sign / personal_sign / signTypedData_v4 and
// obtain this format from the wallet; this helper is the test-harness
// equivalent for SDK keys.
func signEthereumRecoverable(priv *ecdsa.PrivateKey, digest [32]byte) []byte {
	// Convert stdlib *ecdsa.PrivateKey to decred's secp256k1 key type.
	// D.Bytes() may be shorter than 32 bytes due to leading-zero stripping;
	// left-pad to produce the canonical 32-byte scalar.
	d := priv.D.Bytes()
	if len(d) > 32 {
		panic(fmt.Sprintf("test: private key scalar is %d bytes, expected <= 32", len(d)))
	}
	var padded [32]byte
	copy(padded[32-len(d):], d)
	dpriv := decredsecp.PrivKeyFromBytes(padded[:])

	// Decred's SignCompact emits: [v+27 (1 byte)][r (32)][s (32)] — 65 bytes total.
	// Ethereum format is [r][s][v], so swap.
	compact := decredecdsa.SignCompact(dpriv, digest[:], false)
	if len(compact) != 65 {
		panic(fmt.Sprintf("test: unexpected compact signature length %d", len(compact)))
	}
	eth := make([]byte, 65)
	copy(eth[0:32], compact[1:33])   // r
	copy(eth[32:64], compact[33:65]) // s
	eth[64] = compact[0]             // v in 27/28 form
	return eth
}

// -------------------------------------------------------------------------------------------------
// 2) DID:PKH construction from a secp256k1 private key
// -------------------------------------------------------------------------------------------------

// didPKHForKey derives the did:pkh:eip155:1:0x... identifier corresponding
// to the given secp256k1 private key. Returns the DID string and the raw
// 20-byte address for later use in verifier construction.
func didPKHForKey(t testingTB, priv *ecdsa.PrivateKey) (string, [20]byte) {
	t.Helper()
	pub := signatures.PubKeyBytes(&priv.PublicKey)
	addr, err := signatures.AddressFromPubkey(pub)
	if err != nil {
		t.Fatalf("AddressFromPubkey: %v", err)
	}
	return "did:pkh:eip155:1:0x" + hex.EncodeToString(addr[:]), addr
}

// -------------------------------------------------------------------------------------------------
// 3) Stub resolvers
// -------------------------------------------------------------------------------------------------

// panicResolver fails the test if Resolve is ever invoked. Use when a test
// exercises did:pkh or did:key — neither of which should consult the web
// resolver. A call to Resolve indicates the dispatch logic misrouted.
type panicResolver struct{ t testingTB }

func (r panicResolver) Resolve(didStr string) (*did.DIDDocument, error) {
	r.t.Fatalf("panicResolver.Resolve called unexpectedly for %q — did:pkh/did:key must not consult the web resolver", didStr)
	return nil, nil // unreachable
}

// staticResolver returns a pre-built DID document for a specific DID string.
// Used by did:web tests that need a deterministic document without HTTP.
type staticResolver struct {
	wantDID string
	doc     *did.DIDDocument
	err     error
}

func (r *staticResolver) Resolve(didStr string) (*did.DIDDocument, error) {
	if r.err != nil {
		return nil, r.err
	}
	if didStr != r.wantDID {
		return nil, fmt.Errorf("staticResolver: unexpected DID %q, want %q", didStr, r.wantDID)
	}
	return r.doc, nil
}

// -------------------------------------------------------------------------------------------------
// 4) testing.TB polymorphism (shared code across *testing.T and *testing.B)
// -------------------------------------------------------------------------------------------------

// testingTB is the minimal subset of testing.TB used by the helpers above.
// Named here so helpers can be reused from benchmarks if needed.
type testingTB interface {
	Helper()
	Fatalf(format string, args ...interface{})
}

// -------------------------------------------------------------------------------------------------
// 5) Hex utilities
// -------------------------------------------------------------------------------------------------

// mustHex decodes a hex string (with or without 0x prefix), failing the
// test if decoding errors. Intended for literal fixture values.
func mustHex(t testingTB, s string) []byte {
	t.Helper()
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("mustHex(%q): %v", s, err)
	}
	return b
}

// mustHex32 decodes a 32-byte hex literal into a fixed-size array.
func mustHex32(t testingTB, s string) [32]byte {
	t.Helper()
	b := mustHex(t, s)
	if len(b) != 32 {
		t.Fatalf("mustHex32(%q): got %d bytes, want 32", s, len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}
