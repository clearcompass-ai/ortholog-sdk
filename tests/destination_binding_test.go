/*
FILE PATH:

	tests/destination_binding_test.go

DESCRIPTION:

	Locks the destination-binding defense against cross-exchange replay.
	Every test in this file is load-bearing for one invariant; a failure
	anywhere here is either a real security regression or a protocol
	change that requires explicit review.

INVARIANTS LOCKED (14 total):

	DestinationCommitment primitives:
	  1. Deterministic: same input → same output.
	  2. Injective: distinct inputs → distinct outputs.
	  3. Byte-exact: no normalization (case-sensitive).

	ValidateDestination:
	  4. Rejects "" with ErrDestinationEmpty.
	  5. Rejects leading/trailing whitespace with ErrDestinationWhitespace.
	  6. Rejects input over MaxDestinationDIDLen with ErrDestinationTooLong.
	  7. Accepts real-world DID formats (did:web, did:pkh, did:key).

	Integration:
	  8. DestinationCommitment forwards every ValidateDestination error.

	Entry-level validation (uses the SDK's Validate method and NewEntry gate):
	  9. Validate accepts a well-formed Entry.
	 10. Validate rejects an Entry with empty Destination
	     (hand-constructed via struct literal — bypasses NewEntry).
	 11. Validate rejects nil Entry receiver without panicking.
	 12. NewEntry rejects ControlHeader with empty Destination at
	     construction (the complementary gate to #10).

	Cryptographic binding — the keystone:
	 13. VerifyEntry rejects an entry bound to another exchange with
	     ErrDestinationMismatch, even when the signature is
	     cryptographically valid for the claimed signer.
	 14. VerifyEntry accepts an entry bound to its own exchange
	     (positive-path sanity check for #13).

COVERAGE BOUNDARIES — why these, not others:

	Two candidates from the original parked file were intentionally
	dropped because they are redundant with existing coverage:

	  - "CanonicalHash changes with destination" — already locked by
	    TestEntryIdentity_Distinguishes in tests/tessera_compat_test.go.
	  - "Serialize preserves Destination through round-trip" — already
	    locked by TestCanonicalHash_RoundTrip in tests/canonical_hash_test.go,
	    whose fixture populates Destination and asserts byte-stability.

	Duplicating either would add test lines without adding invariants.

KEY DEPENDENCIES:

	core/envelope              Entry, ControlHeader, NewEntry,
	                           EntryIdentity, Serialize,
	                           DestinationCommitment, ValidateDestination,
	                           Err* sentinels, MaxDestinationDIDLen,
	                           SigAlgoECDSA, (*Entry).Validate
	crypto/signatures          SignEntry (secp256k1 R||S)
	did                        GenerateDIDKeySecp256k1,
	                           DefaultVerifierRegistry,
	                           ErrDestinationMismatch
	tests/web3_helpers_test.go panicResolver (panics if web resolution is
	                           attempted; our tests use did:key only)
*/
package tests

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// ─────────────────────────────────────────────────────────────────────
// 1. DestinationCommitment — determinism
// ─────────────────────────────────────────────────────────────────────

func TestDestinationCommitment_Deterministic(t *testing.T) {
	const dest = "did:web:courts.tn.gov:appellate"
	a, err := envelope.DestinationCommitment(dest)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	b, err := envelope.DestinationCommitment(dest)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if a != b {
		t.Fatal("DestinationCommitment is non-deterministic — same input must yield same output")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 2. DestinationCommitment — injective
// ─────────────────────────────────────────────────────────────────────

func TestDestinationCommitment_Injective(t *testing.T) {
	a, err := envelope.DestinationCommitment("did:web:courts.tn.gov:appellate")
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := envelope.DestinationCommitment("did:web:courts.nashville.gov:criminal")
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a == b {
		t.Fatal("distinct destinations produced identical commitments — injectivity violated")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 3. DestinationCommitment — case sensitivity (no normalization)
// ─────────────────────────────────────────────────────────────────────

func TestDestinationCommitment_CaseSensitive(t *testing.T) {
	lower, err := envelope.DestinationCommitment("did:web:a.example.com")
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	upper, err := envelope.DestinationCommitment("did:web:A.example.com")
	if err != nil {
		t.Fatalf("upper: %v", err)
	}
	if lower == upper {
		t.Fatal("case-different DIDs collided — destination comparison must be byte-exact")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 4. ValidateDestination — empty input
// ─────────────────────────────────────────────────────────────────────

func TestValidateDestination_RejectsEmpty(t *testing.T) {
	err := envelope.ValidateDestination("")
	if !errors.Is(err, envelope.ErrDestinationEmpty) {
		t.Fatalf("expected ErrDestinationEmpty, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 5. ValidateDestination — whitespace variants
// ─────────────────────────────────────────────────────────────────────

func TestValidateDestination_RejectsWhitespace(t *testing.T) {
	cases := []string{
		" did:web:a.com",
		"did:web:a.com ",
		"\tdid:web:a.com",
		"did:web:a.com\n",
	}
	for _, bad := range cases {
		err := envelope.ValidateDestination(bad)
		if !errors.Is(err, envelope.ErrDestinationWhitespace) {
			t.Errorf("%q: expected ErrDestinationWhitespace, got %v", bad, err)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// 6. ValidateDestination — length cap
// ─────────────────────────────────────────────────────────────────────

func TestValidateDestination_RejectsOverLong(t *testing.T) {
	// "did:web:" (8 chars) + MaxDestinationDIDLen x's = 8 + 1024 bytes,
	// which comfortably exceeds the 1024-byte cap.
	tooLong := "did:web:" + strings.Repeat("x", envelope.MaxDestinationDIDLen)
	err := envelope.ValidateDestination(tooLong)
	if !errors.Is(err, envelope.ErrDestinationTooLong) {
		t.Fatalf("expected ErrDestinationTooLong, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 7. ValidateDestination — positive cases
// ─────────────────────────────────────────────────────────────────────

func TestValidateDestination_AcceptsRealWorldDIDs(t *testing.T) {
	goods := []string{
		"did:web:courts.tn.gov:appellate",
		"did:pkh:eip155:1:0xabcdef0123456789abcdef0123456789abcdef01",
		"did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSshuhTGhoLjSzhpUPo",
	}
	for _, good := range goods {
		if err := envelope.ValidateDestination(good); err != nil {
			t.Errorf("%q: expected nil, got %v", good, err)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// 8. DestinationCommitment — validation propagation
// ─────────────────────────────────────────────────────────────────────

// DestinationCommitment MUST call ValidateDestination internally — every
// invalid input that ValidateDestination rejects must also be rejected by
// DestinationCommitment. This prevents a consumer from computing a
// commitment over an unvalidated DID and treating the result as
// authoritative.
func TestDestinationCommitment_PropagatesValidation(t *testing.T) {
	cases := map[string]error{
		"":                envelope.ErrDestinationEmpty,
		" did:web:a.com":  envelope.ErrDestinationWhitespace,
		"did:web:a.com\t": envelope.ErrDestinationWhitespace,
	}
	for bad, want := range cases {
		_, err := envelope.DestinationCommitment(bad)
		if !errors.Is(err, want) {
			t.Errorf("%q: expected %v, got %v", bad, want, err)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// 9. Entry.Validate — well-formed entry accepted
// ─────────────────────────────────────────────────────────────────────

// Positive-case guard: prevents Validate from silently degrading into
// "always returns error." An entry produced by NewEntry must, by
// construction, pass Validate.
func TestEntry_Validate_AcceptsWellFormed(t *testing.T) {
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   "did:example:signer",
		Destination: "did:web:test.example",
	}, []byte("payload"))

	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	// v6 requires a well-formed entry to carry at least one signature
	// with Signatures[0].SignerDID == Header.SignerDID. Attach a dummy
	// signature so "well-formed" has its v6 meaning.
	entry.Signatures = []envelope.Signature{{
		SignerDID: "did:example:signer",
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate on well-formed entry: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 10. Entry.Validate — rejects empty Destination via struct literal
// ─────────────────────────────────────────────────────────────────────

// The whole point of Validate existing as a post-hoc method: callers that
// hand-construct Entry via struct literal bypass NewEntry's gate. Validate
// is the safety net that catches them before Serialize / signing / hashing
// treats the malformed entry as authoritative.
func TestEntry_Validate_RejectsEmptyDestination(t *testing.T) {
	e := &envelope.Entry{
		Header: envelope.ControlHeader{
			SignerDID:   "did:example:signer",
			Destination: "",
		},
	}
	err := e.Validate()
	if !errors.Is(err, envelope.ErrDestinationEmpty) {
		t.Fatalf("expected ErrDestinationEmpty from hand-constructed Entry, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 11. Entry.Validate — nil receiver returns error, does not panic
// ─────────────────────────────────────────────────────────────────────

// Fail-loud guard: a nil *Entry must surface an error, not a runtime panic.
// Protects callers from accidental crashes when validating entries read
// from untrusted sources (e.g., decoded maps, sparse fixtures).
func TestEntry_Validate_RejectsNil(t *testing.T) {
	var e *envelope.Entry
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Validate on nil Entry must not panic; got panic: %v", r)
		}
	}()
	if err := e.Validate(); err == nil {
		t.Fatal("Validate on nil Entry must return an error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 12. NewEntry — rejects empty Destination at construction
// ─────────────────────────────────────────────────────────────────────

// Complementary gate to TestEntry_Validate_RejectsEmptyDestination. Same
// invariant (no entry may have empty Destination), different entry point
// (canonical constructor vs. post-hoc validator).
func TestNewEntry_RejectsEmptyDestination(t *testing.T) {
	_, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   "did:example:signer",
		Destination: "",
	}, nil)

	if !errors.Is(err, envelope.ErrDestinationEmpty) {
		t.Fatalf("expected ErrDestinationEmpty at construction, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 13. KEYSTONE — cross-destination verification rejected
// ─────────────────────────────────────────────────────────────────────

// The single most important test in this file. Constructs a
// cryptographically valid signed entry bound to exchange A, then attempts
// to verify it through a VerifierRegistry scoped to exchange B. A failure
// here is a cross-exchange replay vulnerability.
//
// Must return did.ErrDestinationMismatch — the specific sentinel. Matching
// on error strings would be brittle; sentinel matching ensures the
// rejection is for the right reason.
func TestVerifyEntry_CrossDestination_Rejected(t *testing.T) {
	const (
		destA = "did:web:exchange-a.example"
		destB = "did:web:exchange-b.example"
	)

	// Generate a secp256k1 keypair and the corresponding did:key.
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
	}

	// Build an entry legitimately bound to destA.
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   kp.DID,
		Destination: destA,
	}, []byte("cross-destination-test-payload"))

	if err != nil {
		t.Fatalf("NewEntry(destA): %v", err)
	}

	// Sign the v6 signing payload hash. Under v6 signers compute
	// sha256(SigningPayload(entry)) — the pre-signature bytes — since
	// EntryIdentity (= sha256(Serialize(entry))) requires the signatures
	// to already be present. This is the hash the registry recomputes
	// from the received entry before verification.
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(hash, kp.PrivateKey)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}

	// Build a registry scoped to destB. panicResolver is fine here — our
	// test uses did:key exclusively, which resolves by parsing the
	// identifier; the web resolver is never invoked.
	// Attach the signature to the entry under v6 semantics (signatures
	// live inside entry.Signatures; the registry reads them from there).
	entry.Signatures = []envelope.Signature{{
		SignerDID: kp.DID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate signed entry: %v", err)
	}

	registryForB := did.DefaultVerifierRegistry(destB, panicResolver{})

	// Attempt verification. Must fail with ErrDestinationMismatch.
	err = registryForB.VerifyEntry(entry)
	if err == nil {
		t.Fatal("registry scoped to destB accepted entry bound to destA — cross-exchange replay possible")
	}
	if !errors.Is(err, did.ErrDestinationMismatch) {
		t.Fatalf("expected did.ErrDestinationMismatch, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 14. Positive path — same-destination verification succeeds
// ─────────────────────────────────────────────────────────────────────

// Sanity check for the keystone test. If verification somehow fails here,
// the keystone test's negative assertion becomes meaningless — the
// rejection in test 13 could be for an unrelated reason (bad keygen, bad
// signature, wrong algoID) rather than destination mismatch.
func TestVerifyEntry_SameDestination_Accepted(t *testing.T) {
	const dest = "did:web:exchange-a.example"

	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
	}

	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   kp.DID,
		Destination: dest,
	}, []byte("same-destination-test-payload"))

	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}

	// Sign the v6 signing payload hash. See test #13 rationale above.
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(hash, kp.PrivateKey)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}

	// Attach the signature to the entry under v6 semantics.
	entry.Signatures = []envelope.Signature{{
		SignerDID: kp.DID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate signed entry: %v", err)
	}

	registry := did.DefaultVerifierRegistry(dest, panicResolver{})

	if err := registry.VerifyEntry(entry); err != nil {
		t.Fatalf("same-destination VerifyEntry: %v", err)
	}
}
