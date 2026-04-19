/*
FILE PATH:

	tests/web3_fuzz_test.go

DESCRIPTION:

	Fuzz targets for parsers and validators that accept untrusted input.
	A single panic in any of these is a denial-of-service vector: an attacker
	feeds a malformed DID, envelope, or signature to a public endpoint and
	takes down the process.

KEY ARCHITECTURAL DECISIONS:
  - Every fuzz target follows the same contract: "MUST NOT panic for any
    byte sequence." It does not assert that the parser returns a specific
    answer — only that it returns *some* answer, error or otherwise, without
    crashing the process.
  - Seed corpora include known-valid inputs (for coverage) and known-hostile
    inputs (empty, truncated, boundary lengths, mismatched prefixes) to give
    the fuzzer a head start.
  - Run nightly: `go test -fuzz=FuzzParseDIDPKH -fuzztime=10m ./tests`.
    In per-PR CI, these exist as smoke tests; real fuzz budget is nightly.
  - Under v6, FuzzStripSignature was replaced with FuzzDeserialize. The
    v5 wire-primitive StripSignature was removed; envelope.Deserialize is
    the new untrusted-input boundary for the wire format.
*/
package tests

import (
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/auth"
)

// -------------------------------------------------------------------------------------------------
// 1) FuzzParseDIDPKH — did:pkh identifier parser
// -------------------------------------------------------------------------------------------------

// FuzzParseDIDPKH asserts that ParseDIDPKH never panics on any input string.
// Seed corpus includes the empty string, valid identifiers, and common
// malformations (missing colons, non-hex addresses, unicode).
func FuzzParseDIDPKH(f *testing.F) {
	seeds := []string{
		"",
		"did:pkh:eip155:1:0x0000000000000000000000000000000000000000",
		"did:pkh:eip155:1:0xABCDEF0123456789ABCDEF0123456789ABCDEF01",
		"did:pkh:eip155::0x0000000000000000000000000000000000000000",
		"did:pkh::1:0x0000000000000000000000000000000000000000",
		"did:pkh:eip155:1:",
		"did:pkh:eip155:1:0x", // truncated address
		"did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:AhwZzLjCkVRAB",
		"did:pkh:eip155:1:0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG", // non-hex
		"did:pkh:eip155:1:0x\x00\x00\x00\x00",                         // nulls
		"did:pkh",
		"did:pkh:",
		"did:pkh:::::::",
		"not a did at all",
		"did:pkh:eip155:1:\u00ff0xabcd", // non-ASCII
		"did:pkh:eip155:1:0xabcdef0123456789abcdef0123456789abcdef01", // valid lower
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = did.ParseDIDPKH(input) // MUST NOT panic
	})
}

// -------------------------------------------------------------------------------------------------
// 2) FuzzParseDIDKey — did:key identifier parser
// -------------------------------------------------------------------------------------------------

func FuzzParseDIDKey(f *testing.F) {
	// Generate one valid did:key seed across each curve.
	seeds := []string{
		"",
		"did:key:",
		"did:key:z",
		"did:key:f00",   // legacy non-standard format
		"did:key:z6Mki", // too short
		"did:key:z\x00\x00\x00\x00\x00",
		"not a did:key at all",
		"did:key:zBADBASE58???", // invalid base58 characters
		"did:key:xABCDEF",       // unsupported multibase
	}
	// Add a dynamically-generated valid seed per curve if possible.
	if kp, err := did.GenerateDIDKeySecp256k1(); err == nil {
		seeds = append(seeds, kp.DID)
	}
	if kp, err := did.GenerateDIDKeyEd25519(); err == nil {
		seeds = append(seeds, kp.DID)
	}
	if kp, err := did.GenerateDIDKeyP256(); err == nil {
		seeds = append(seeds, kp.DID)
	}

	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, _, _ = did.ParseDIDKey(input) // MUST NOT panic
	})
}

// -------------------------------------------------------------------------------------------------
// 3) FuzzDeserialize — wire-format reverse-engineering (v6 replacement)
// -------------------------------------------------------------------------------------------------

// FuzzDeserialize hammers the v6 entry decode path with arbitrary byte
// sequences. This replaces the v5 FuzzStripSignature target — the
// envelope.StripSignature function was removed in v6, and Deserialize
// is the new untrusted-input boundary for the wire format.
//
// Contract: Deserialize MUST NOT panic for any byte sequence. Malformed
// inputs must produce wrapped errors, not crashes.
func FuzzDeserialize(f *testing.F) {
	// Seed with valid serialized entries across all registered
	// signature algorithms, to give the fuzzer realistic starting points.
	for _, algoCase := range []struct {
		algoID uint16
		sigLen int
	}{
		{envelope.SigAlgoECDSA, 64},
		{envelope.SigAlgoEd25519, 64},
		{envelope.SigAlgoEIP191, 65},
		{envelope.SigAlgoEIP712, 65},
		{envelope.SigAlgoJWZ, 512},
	} {
		const signerDID = "did:example:fuzzseed"
		entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
			Destination: testDestinationDID,
			SignerDID:   signerDID,
		}, []byte("fuzz seed payload"))
		if err != nil {
			continue
		}
		entry.Signatures = []envelope.Signature{{
			SignerDID: signerDID,
			AlgoID:    algoCase.algoID,
			Bytes:     make([]byte, algoCase.sigLen),
		}}
		if err := entry.Validate(); err == nil {
			f.Add(envelope.Serialize(entry))
		}
	}
	// Seed with pathological inputs.
	f.Add([]byte{})
	f.Add([]byte{0x00})
	// Length-prefix edge cases and boundary sizes.
	for _, n := range []int{1, 2, 3, 4, 5, 6, 7, 8, 10, 16, 32, 64, 100, 128, 256} {
		f.Add(make([]byte, n))
	}

	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = envelope.Deserialize(wire) // MUST NOT panic
	})
}

// -------------------------------------------------------------------------------------------------
// 4) FuzzValidateAlgorithmID — algorithm ID classifier
// -------------------------------------------------------------------------------------------------

// FuzzValidateAlgorithmID is a trivial target but it locks the contract that
// ValidateAlgorithmID is a total function over uint16. Any future refactor
// that makes it panic on a specific input is caught immediately.
//
// v6 removed the SignatureLengthForAlgorithm call; only ValidateAlgorithmID
// remains.
func FuzzValidateAlgorithmID(f *testing.F) {
	for _, v := range []uint16{0, 1, 2, 3, 4, 5, 0xFFFF, 0xBEEF, 0xDEAD} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, algoID uint16) {
		_ = envelope.ValidateAlgorithmID(algoID) // MUST NOT panic
	})
}

// -------------------------------------------------------------------------------------------------
// 5) FuzzCanonicalizeSignedRequest — exchange/auth envelope canonicalization
// -------------------------------------------------------------------------------------------------

// FuzzCanonicalizeSignedRequest asserts that Canonicalize never panics,
// regardless of input shape. Malformed envelopes must produce errors, not
// crashes. The target feeds individual fields as fuzzer-controlled to
// maximize coverage of the length-prefixed encoding edge cases.
func FuzzCanonicalizeSignedRequest(f *testing.F) {
	// Valid seed
	f.Add(
		/* did      */ "did:pkh:eip155:1:0x0000000000000000000000000000000000000000",
		/* domain   */ "exchange.example.com",
		/* chain    */ "1",
		/* nonce    */ "abc-123",
		/* method   */ "POST",
		/* path     */ "/v1/entries",
		/* issuedAt */ int64(1700000000),
		/* expAt    */ int64(1700000300),
	)
	// Pathological seeds
	f.Add("", "", "", "", "", "", int64(0), int64(0))
	f.Add(
		"did:pkh:eip155:1:0x0000000000000000000000000000000000000000",
		"exchange.example.com",
		"",
		"n",
		"get", // wrong case
		"/v1/x",
		int64(1700000000),
		int64(1700000300),
	)

	f.Fuzz(func(t *testing.T,
		didStr, domain, chainID, nonce, method, path string,
		issuedAtUnix, expiresAtUnix int64,
	) {
		env := &auth.SignedRequestEnvelope{
			Version:   auth.EnvelopeVersion,
			DID:       didStr,
			Domain:    domain,
			ChainID:   chainID,
			Nonce:     nonce,
			Method:    method,
			Path:      path,
			IssuedAt:  unixToTime(issuedAtUnix),
			ExpiresAt: unixToTime(expiresAtUnix),
		}
		// BodyHash left at zero-value. Canonicalize MUST NOT panic.
		_, _ = env.Canonicalize()
		_, _ = env.CanonicalHash()
	})
}

// -------------------------------------------------------------------------------------------------
// 6) FuzzExtractMethod — DID method extraction
// -------------------------------------------------------------------------------------------------

// FuzzExtractMethod hammers the tiny DID-method extraction utility. It runs
// on every verifier dispatch, so a panic here is a DoS against every
// verify call path.
func FuzzExtractMethod(f *testing.F) {
	for _, s := range []string{
		"",
		"did:",
		"did::",
		"did:pkh",
		"did:pkh:",
		"did:web:example.com",
		"did:key:z6Mki",
		"not-a-did",
		"did:\x00\x00",
		"did:pkh:eip155:1:0xabcd",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = did.ExtractMethod(input) // MUST NOT panic
	})
}

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

// unixToTime converts a unix second count to time.Time, clamping to zero for
// negative values to avoid constructing times outside the valid range.
func unixToTime(unix int64) (t time.Time) {
	if unix < 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0).UTC()
}
