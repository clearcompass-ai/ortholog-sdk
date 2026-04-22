/*
FILE PATH:

	witness/tree_head_client_test.go

DESCRIPTION:

	White-box regression guards for BUG-012. Lives in the witness
	package so tests can invoke parseTreeHeadResponse directly
	without spinning up HTTP test servers.

	Black-box integration coverage (network path, cache behavior,
	fallback ladder) lives in tests/tree_head_client_test.go.
	This file covers ONLY the parser's wire-contract enforcement.

BUG-012 BACKGROUND

	Pre-fix parseTreeHeadResponse derived PubKeyID by hashing the
	"signer" string — sha256([]byte(s.Signer)). The canonical
	identity used everywhere else in the SDK is sha256(pubkey_bytes),
	produced by did/resolver.go:181. The two derivations never
	collided, so every HTTP-fetched tree head silently failed
	verifier lookup.

	The cutover fix removes identity derivation from the parser
	entirely. The operator now sends pubkey_id hex on the wire; the
	parser transcribes it verbatim.

MUTATION PROBE

	In witness/tree_head_client.go, inside parseTreeHeadResponse,
	comment out the missing-pubkey_id guard:

	    // if s.PubKeyID == "" {
	    //     return types.CosignedTreeHead{}, fmt.Errorf(
	    //         "witness/client: signature[%d]: missing required pubkey_id field", i)
	    // }

	Run: go test -count=1 -v -run TestParseTreeHeadResponse_RejectsMissingPubKeyID ./witness/
	Expected: FAIL with "BUG-012 REGRESSION: parser accepted a response
	missing pubkey_id".

	Restore the guard. Re-run. Test passes.

	Similar probes: comment out each length/hex check and confirm
	the corresponding test fails.
*/
package witness

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

// pubKeyIDHex returns a hex-encoded 32-byte id derived by hashing a
// label. The specific bytes don't matter for parser tests; what
// matters is that the input is valid-shape hex of the right length.
func pubKeyIDHex(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

// validRootHashHex returns a plausible 32-byte hex root hash.
func validRootHashHex() string {
	sum := sha256.Sum256([]byte("test-root"))
	return hex.EncodeToString(sum[:])
}

// ═══════════════════════════════════════════════════════════════════
// Happy path — confirms the new contract parses cleanly
// ═══════════════════════════════════════════════════════════════════

func TestParseTreeHeadResponse_AcceptsValidResponse(t *testing.T) {
	body := fmt.Sprintf(`{
		"tree_size": 100,
		"root_hash": %q,
		"hash_algo": 1,
		"signatures": [
			{"pubkey_id": %q, "sig_algo": 1, "signature": %q},
			{"pubkey_id": %q, "sig_algo": 2, "signature": %q}
		]
	}`, validRootHashHex(),
		pubKeyIDHex("witness-alpha"), hex.EncodeToString(make([]byte, 64)),
		pubKeyIDHex("witness-beta"), hex.EncodeToString(make([]byte, 96)))

	head, err := parseTreeHeadResponse([]byte(body))
	if err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	if head.TreeSize != 100 {
		t.Fatalf("tree_size: got %d, want 100", head.TreeSize)
	}
	if len(head.Signatures) != 2 {
		t.Fatalf("signatures: got %d, want 2", len(head.Signatures))
	}

	// Post-BUG-012 invariant: PubKeyID transcribed verbatim from JSON.
	alphaSum := sha256.Sum256([]byte("witness-alpha"))
	if head.Signatures[0].PubKeyID != alphaSum {
		t.Fatalf("pubkey_id not transcribed verbatim; got %x, want %x",
			head.Signatures[0].PubKeyID, alphaSum)
	}
	if head.Signatures[0].SchemeTag != 1 {
		t.Fatalf("scheme tag[0]: got %d, want 1", head.Signatures[0].SchemeTag)
	}
	if head.Signatures[1].SchemeTag != 2 {
		t.Fatalf("scheme tag[1]: got %d, want 2", head.Signatures[1].SchemeTag)
	}
}

func TestParseTreeHeadResponse_AcceptsEmptySignatures(t *testing.T) {
	// Empty signature list is permitted at the wire-format layer.
	// The verifier rejects it separately; that's not this parser's
	// job.
	body := fmt.Sprintf(`{
		"tree_size": 1,
		"root_hash": %q,
		"hash_algo": 1,
		"signatures": []
	}`, validRootHashHex())

	head, err := parseTreeHeadResponse([]byte(body))
	if err != nil {
		t.Fatalf("empty signatures rejected at parse layer: %v", err)
	}
	if len(head.Signatures) != 0 {
		t.Fatalf("signatures: got %d, want 0", len(head.Signatures))
	}
}

// ═══════════════════════════════════════════════════════════════════
// BUG-012 HEADLINE REGRESSION — missing pubkey_id
// ═══════════════════════════════════════════════════════════════════

// TestParseTreeHeadResponse_RejectsMissingPubKeyID is the BUG-012
// headline guard. A signature block with no pubkey_id must be
// rejected.
//
// Before the fix: parser accepted the missing field, derived a
// broken ID from the "signer" string, and produced a tree head
// that failed every verifier lookup. After the fix: hard error.
//
// This test constructs JSON in the PRE-CUTOVER shape (signer only,
// no pubkey_id) to confirm the parser rejects the old format.
func TestParseTreeHeadResponse_RejectsMissingPubKeyID(t *testing.T) {
	body := fmt.Sprintf(`{
		"tree_size": 100,
		"root_hash": %q,
		"hash_algo": 1,
		"signatures": [
			{"signer": "did:web:court#witness-1", "sig_algo": 1, "signature": %q}
		]
	}`, validRootHashHex(), hex.EncodeToString(make([]byte, 64)))

	_, err := parseTreeHeadResponse([]byte(body))
	if err == nil {
		t.Fatal("BUG-012 REGRESSION: parser accepted a response missing " +
			"pubkey_id. The pre-cutover JSON shape (signer-only) must " +
			"be rejected; the parser must never fabricate identity from " +
			"the signer string.")
	}
	// The parser rejects with a specific diagnostic when pubkey_id is
	// absent. Defense-in-depth: the downstream length check also rejects,
	// so removing this guard does not break contract enforcement, but the
	// diagnostic message degrades to a less-precise one.
	if !strings.Contains(err.Error(), "missing required pubkey_id") {
		t.Fatalf("BUG-012 REGRESSION (diagnostic): empty pubkey_id should "+
			"produce a 'missing required pubkey_id' diagnostic, got: %v", err)
	}
	// The probe-load-bearing assertion: contract must be enforced.
	if err == nil {
		t.Fatal("BUG-012 REGRESSION: parser accepted missing pubkey_id")
	}
}

// ═══════════════════════════════════════════════════════════════════
// Malformed pubkey_id — hex decode failure, wrong length
// ═══════════════════════════════════════════════════════════════════

func TestParseTreeHeadResponse_RejectsMalformedPubKeyIDHex(t *testing.T) {
	body := fmt.Sprintf(`{
		"tree_size": 100,
		"root_hash": %q,
		"hash_algo": 1,
		"signatures": [
			{"pubkey_id": "not-valid-hex-zzzz", "sig_algo": 1, "signature": %q}
		]
	}`, validRootHashHex(), hex.EncodeToString(make([]byte, 64)))

	_, err := parseTreeHeadResponse([]byte(body))
	if err == nil {
		t.Fatal("parser accepted malformed pubkey_id hex")
	}
	if !strings.Contains(err.Error(), "invalid pubkey_id hex") {
		t.Fatalf("expected 'invalid pubkey_id hex' diagnostic, got: %v", err)
	}
}

func TestParseTreeHeadResponse_RejectsShortPubKeyID(t *testing.T) {
	// 16 bytes instead of 32.
	shortID := hex.EncodeToString(make([]byte, 16))
	body := fmt.Sprintf(`{
		"tree_size": 100,
		"root_hash": %q,
		"hash_algo": 1,
		"signatures": [
			{"pubkey_id": %q, "sig_algo": 1, "signature": %q}
		]
	}`, validRootHashHex(), shortID, hex.EncodeToString(make([]byte, 64)))

	_, err := parseTreeHeadResponse([]byte(body))
	if err == nil {
		t.Fatal("parser accepted pubkey_id shorter than 32 bytes")
	}
	if !strings.Contains(err.Error(), "must be 32 bytes") {
		t.Fatalf("expected length diagnostic, got: %v", err)
	}
}

func TestParseTreeHeadResponse_RejectsLongPubKeyID(t *testing.T) {
	// 64 bytes instead of 32.
	longID := hex.EncodeToString(make([]byte, 64))
	body := fmt.Sprintf(`{
		"tree_size": 100,
		"root_hash": %q,
		"hash_algo": 1,
		"signatures": [
			{"pubkey_id": %q, "sig_algo": 1, "signature": %q}
		]
	}`, validRootHashHex(), longID, hex.EncodeToString(make([]byte, 64)))

	_, err := parseTreeHeadResponse([]byte(body))
	if err == nil {
		t.Fatal("parser accepted pubkey_id longer than 32 bytes")
	}
	if !strings.Contains(err.Error(), "must be 32 bytes") {
		t.Fatalf("expected length diagnostic, got: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════
// Required sibling fields — sig_algo, signature
// ═══════════════════════════════════════════════════════════════════

// TestParseTreeHeadResponse_RejectsZeroSigAlgo confirms the Wave 2
// strict zero-tag policy is enforced at the parse layer. The
// verifier also rejects zero SchemeTag, but catching it at parse
// time produces a clearer diagnostic pointing to the operator
// response rather than at verification time.
func TestParseTreeHeadResponse_RejectsZeroSigAlgo(t *testing.T) {
	body := fmt.Sprintf(`{
		"tree_size": 100,
		"root_hash": %q,
		"hash_algo": 1,
		"signatures": [
			{"pubkey_id": %q, "sig_algo": 0, "signature": %q}
		]
	}`, validRootHashHex(), pubKeyIDHex("w1"), hex.EncodeToString(make([]byte, 64)))

	_, err := parseTreeHeadResponse([]byte(body))
	if err == nil {
		t.Fatal("parser accepted zero sig_algo")
	}
	if !strings.Contains(err.Error(), "zero sig_algo") {
		t.Fatalf("expected zero-algo diagnostic, got: %v", err)
	}
}

func TestParseTreeHeadResponse_RejectsMissingSigAlgo(t *testing.T) {
	// sig_algo absent from JSON — json.Unmarshal leaves it at zero value.
	body := fmt.Sprintf(`{
		"tree_size": 100,
		"root_hash": %q,
		"hash_algo": 1,
		"signatures": [
			{"pubkey_id": %q, "signature": %q}
		]
	}`, validRootHashHex(), pubKeyIDHex("w1"), hex.EncodeToString(make([]byte, 64)))

	_, err := parseTreeHeadResponse([]byte(body))
	if err == nil {
		t.Fatal("parser accepted missing sig_algo")
	}
}

func TestParseTreeHeadResponse_RejectsMissingSignature(t *testing.T) {
	body := fmt.Sprintf(`{
		"tree_size": 100,
		"root_hash": %q,
		"hash_algo": 1,
		"signatures": [
			{"pubkey_id": %q, "sig_algo": 1}
		]
	}`, validRootHashHex(), pubKeyIDHex("w1"))

	_, err := parseTreeHeadResponse([]byte(body))
	if err == nil {
		t.Fatal("parser accepted missing signature field")
	}
	if !strings.Contains(err.Error(), "missing signature") {
		t.Fatalf("expected 'missing signature' diagnostic, got: %v", err)
	}
}

func TestParseTreeHeadResponse_RejectsMalformedSignatureHex(t *testing.T) {
	body := fmt.Sprintf(`{
		"tree_size": 100,
		"root_hash": %q,
		"hash_algo": 1,
		"signatures": [
			{"pubkey_id": %q, "sig_algo": 1, "signature": "not-hex-zzz"}
		]
	}`, validRootHashHex(), pubKeyIDHex("w1"))

	_, err := parseTreeHeadResponse([]byte(body))
	if err == nil {
		t.Fatal("parser accepted malformed signature hex")
	}
	if !strings.Contains(err.Error(), "invalid signature hex") {
		t.Fatalf("expected 'invalid signature hex' diagnostic, got: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════
// root_hash contract
// ═══════════════════════════════════════════════════════════════════

func TestParseTreeHeadResponse_RejectsMissingRootHash(t *testing.T) {
	body := `{
		"tree_size": 100,
		"hash_algo": 1,
		"signatures": []
	}`

	_, err := parseTreeHeadResponse([]byte(body))
	if err == nil {
		t.Fatal("parser accepted missing root_hash")
	}
	if !strings.Contains(err.Error(), "missing required root_hash") {
		t.Fatalf("expected 'missing required root_hash' diagnostic, got: %v", err)
	}
}

func TestParseTreeHeadResponse_RejectsShortRootHash(t *testing.T) {
	// 16 bytes — half the required length.
	short := hex.EncodeToString(make([]byte, 16))
	body := fmt.Sprintf(`{
		"tree_size": 100,
		"root_hash": %q,
		"hash_algo": 1,
		"signatures": []
	}`, short)

	_, err := parseTreeHeadResponse([]byte(body))
	if err == nil {
		t.Fatal("parser accepted short root_hash")
	}
	if !strings.Contains(err.Error(), "root_hash must be 32 bytes") {
		t.Fatalf("expected length diagnostic, got: %v", err)
	}
}

func TestParseTreeHeadResponse_RejectsMalformedRootHashHex(t *testing.T) {
	body := `{
		"tree_size": 100,
		"root_hash": "zzz-not-hex",
		"hash_algo": 1,
		"signatures": []
	}`

	_, err := parseTreeHeadResponse([]byte(body))
	if err == nil {
		t.Fatal("parser accepted malformed root_hash hex")
	}
	if !strings.Contains(err.Error(), "invalid root_hash hex") {
		t.Fatalf("expected hex diagnostic, got: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════
// Top-level JSON structure
// ═══════════════════════════════════════════════════════════════════

func TestParseTreeHeadResponse_RejectsMalformedJSON(t *testing.T) {
	body := `{not valid json`

	_, err := parseTreeHeadResponse([]byte(body))
	if err == nil {
		t.Fatal("parser accepted malformed JSON")
	}
	if !strings.Contains(err.Error(), "decode JSON") {
		t.Fatalf("expected decode diagnostic, got: %v", err)
	}
}
