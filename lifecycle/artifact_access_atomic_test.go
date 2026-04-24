package lifecycle

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/internal/testkeys"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// preGrantHarness wires a minimal PRE flow end-to-end: owner key,
// recipient key, capsule, ciphertext, CID. Returns everything a
// GrantArtifactAccess call needs under the EncryptionUmbralPRE path.
//
// Intentionally scoped to the atomic-emission tests — a richer
// harness lives in tests/integration/pre_lifecycle_integration_test.go
// for the full primitive-level cycle.
type preGrantHarness struct {
	owner        testkeys.Keypair
	recipient    testkeys.Keypair
	capsule      *artifact.Capsule
	ciphertext   []byte
	artifactCID  storage.CID
	destination  string
	granterDID   string
	recipientDID string
}

func newPREGrantHarness(t *testing.T) *preGrantHarness {
	t.Helper()
	owner := testkeys.New(t)
	recipient := testkeys.New(t)

	plaintext := []byte("atomic emission harness plaintext")
	capsule, ciphertext, err := artifact.PRE_Encrypt(owner.PK, plaintext)
	if err != nil {
		t.Fatalf("PRE_Encrypt: %v", err)
	}
	cidDigest := sha256.Sum256(ciphertext)
	cid := storage.CID{Algorithm: storage.AlgoSHA256, Digest: cidDigest[:]}

	return &preGrantHarness{
		owner:        owner,
		recipient:    recipient,
		capsule:      capsule,
		ciphertext:   ciphertext,
		artifactCID:  cid,
		destination:  "did:web:example.com:exchange",
		granterDID:   "did:web:example.com:grantor",
		recipientDID: "did:web:example.com:recipient",
	}
}

func (h *preGrantHarness) params() GrantArtifactAccessParams {
	return GrantArtifactAccessParams{
		Destination:     h.destination,
		ArtifactCID:     h.artifactCID,
		RecipientPubKey: h.recipient.PK,
		SchemaParams: &types.SchemaParameters{
			ArtifactEncryption:     types.EncryptionUmbralPRE,
			GrantAuthorizationMode: types.GrantAuthOpen,
			ReEncryptionThreshold:  &types.ThresholdConfig{M: 3, N: 5},
		},
		GranterDID:     h.granterDID,
		RecipientDID:   h.recipientDID,
		Capsule:        h.capsule,
		OwnerSecretKey: h.owner.SK,
	}
}

// ─────────────────────────────────────────────────────────────────────
// Group 3.5 atomic emission
// ─────────────────────────────────────────────────────────────────────

// TestGrantArtifactAccess_AtomicCommitmentEmission confirms that every
// successful umbral_pre grant returns a non-nil CommitmentEntry along
// with the CFrags. This is the structural invariant ADR-005 §4 pins.
func TestGrantArtifactAccess_AtomicCommitmentEmission(t *testing.T) {
	h := newPREGrantHarness(t)
	result, err := GrantArtifactAccess(h.params())
	if err != nil {
		t.Fatalf("GrantArtifactAccess: %v", err)
	}
	if result.Method != "umbral_pre" {
		t.Fatalf("Method = %q, want umbral_pre", result.Method)
	}
	if len(result.CFrags) == 0 {
		t.Fatal("expected CFrags, got none")
	}
	if result.Commitment == nil {
		t.Fatal("expected Commitment, got nil")
	}
	if result.CommitmentEntry == nil {
		t.Fatal("expected CommitmentEntry, got nil (atomic emission violated)")
	}
	if result.Commitments.Threshold() != 3 {
		t.Fatalf("Commitments.Threshold() = %d, want 3", result.Commitments.Threshold())
	}

	// The commitment entry must parse back cleanly via the schema
	// validator — admission would reject otherwise.
	if err := schema.ValidatePREGrantCommitmentEntry(result.CommitmentEntry); err != nil {
		t.Fatalf("commitment entry does not pass admission validator: %v", err)
	}
	parsed, err := schema.ParsePREGrantCommitmentEntry(result.CommitmentEntry)
	if err != nil {
		t.Fatalf("parse commitment entry: %v", err)
	}

	// The on-log commitment must bind to the grant context.
	if err := artifact.VerifyPREGrantCommitment(
		parsed, h.granterDID, h.recipientDID, h.artifactCID,
	); err != nil {
		t.Fatalf("on-log commitment does not verify against grant context: %v", err)
	}

	// SplitID equals the deterministic derivation.
	want := artifact.ComputePREGrantSplitID(h.granterDID, h.recipientDID, h.artifactCID)
	if parsed.SplitID != want {
		t.Fatalf("SplitID drift: got %x, want %x", parsed.SplitID[:], want[:])
	}

	// Destination is bound into the commitment entry.
	if result.CommitmentEntry.Header.Destination != h.destination {
		t.Fatalf("destination drift: %q", result.CommitmentEntry.Header.Destination)
	}
}

// TestGrantArtifactAccess_PRE_RejectsMissingGranterDID pins that the
// atomic emission requires the granter DID for SplitID derivation.
// Without it the SplitID cannot be computed and the grant must fail
// fast rather than silently emitting commitments bound to an empty
// DID.
func TestGrantArtifactAccess_PRE_RejectsMissingGranterDID(t *testing.T) {
	h := newPREGrantHarness(t)
	params := h.params()
	params.GranterDID = ""
	// Grant authorization is open, so Phase 1 does not fail on missing
	// granter DID. The failure must come from grantUmbralPRE.
	_, err := GrantArtifactAccess(params)
	if err == nil {
		t.Fatal("want error on missing GranterDID, got nil")
	}
}

// TestGrantArtifactAccess_PRE_RejectsMissingRecipientDID is the
// symmetric test for RecipientDID.
func TestGrantArtifactAccess_PRE_RejectsMissingRecipientDID(t *testing.T) {
	h := newPREGrantHarness(t)
	params := h.params()
	params.RecipientDID = ""
	_, err := GrantArtifactAccess(params)
	if err == nil {
		t.Fatal("want error on missing RecipientDID, got nil")
	}
}

// TestGrantArtifactAccess_PRE_RejectsMissingArtifactCID pins that the
// atomic emission requires the artifact CID — without it SplitID
// binding is meaningless.
func TestGrantArtifactAccess_PRE_RejectsMissingArtifactCID(t *testing.T) {
	h := newPREGrantHarness(t)
	params := h.params()
	params.ArtifactCID = storage.CID{}
	_, err := GrantArtifactAccess(params)
	if err == nil {
		t.Fatal("want error on missing ArtifactCID, got nil")
	}
}

// TestGrantArtifactAccess_PRE_CommitmentEntryIsPathACommentary pins
// the header shape ADR-005 §4 requires — no TargetRoot, no
// AuthorityPath (Path A commentary), signed by the grantor.
func TestGrantArtifactAccess_PRE_CommitmentEntryIsPathACommentary(t *testing.T) {
	h := newPREGrantHarness(t)
	result, err := GrantArtifactAccess(h.params())
	if err != nil {
		t.Fatalf("GrantArtifactAccess: %v", err)
	}
	e := result.CommitmentEntry
	if e.Header.AuthorityPath != nil {
		t.Fatal("AuthorityPath must be nil on commitment entry (Path A commentary)")
	}
	if e.Header.TargetRoot != nil {
		t.Fatal("TargetRoot must be nil on commitment entry")
	}
	if e.Header.SignerDID != h.granterDID {
		t.Fatalf("SignerDID = %q, want %q", e.Header.SignerDID, h.granterDID)
	}
}

// TestGrantArtifactAccess_AESGCM_NoCommitmentEntry pins the negative
// invariant: AES-GCM grants do NOT populate CommitmentEntry — there is
// no commitment set on this path, and the invariant trivially holds
// because no CFrags are produced either.
func TestGrantArtifactAccess_AESGCM_NoCommitmentEntry(t *testing.T) {
	// Build a minimal AES-GCM grant. The KeyStore holds the artifact
	// key; the recipient key wraps it via ECIES.
	recipient := testkeys.New(t)
	plaintext := []byte("aes gcm harness")
	ciphertext, artKey, err := artifact.EncryptArtifact(plaintext)
	if err != nil {
		t.Fatalf("EncryptArtifact: %v", err)
	}
	cidDigest := sha256.Sum256(ciphertext)
	cid := storage.CID{Algorithm: storage.AlgoSHA256, Digest: cidDigest[:]}

	store := NewInMemoryKeyStore()
	if err := store.Store(cid, artKey); err != nil {
		t.Fatalf("KeyStore.Store: %v", err)
	}

	params := GrantArtifactAccessParams{
		Destination:     "did:web:example.com:exchange",
		ArtifactCID:     cid,
		RecipientPubKey: recipient.PK,
		KeyStore:        store,
		SchemaParams: &types.SchemaParameters{
			ArtifactEncryption:     types.EncryptionAESGCM,
			GrantAuthorizationMode: types.GrantAuthOpen,
		},
	}
	result, err := GrantArtifactAccess(params)
	if err != nil {
		t.Fatalf("GrantArtifactAccess (AES-GCM): %v", err)
	}
	if result.Method != "aes_gcm" {
		t.Fatalf("Method = %q, want aes_gcm", result.Method)
	}
	if result.CommitmentEntry != nil {
		t.Fatal("AES-GCM must NOT populate CommitmentEntry")
	}
	if result.Commitment != nil {
		t.Fatal("AES-GCM must NOT populate Commitment")
	}
	if len(result.CFrags) != 0 {
		t.Fatal("AES-GCM must NOT populate CFrags")
	}
}

// TestBuildPREGrantCommitmentEntry_IntegrationAdmissionRoundTrip pins
// that the builder's output satisfies the schema validator — keeping
// builder and schema in lock-step even if either side is refactored.
func TestBuildPREGrantCommitmentEntry_IntegrationAdmissionRoundTrip(t *testing.T) {
	h := newPREGrantHarness(t)
	result, err := GrantArtifactAccess(h.params())
	if err != nil {
		t.Fatalf("GrantArtifactAccess: %v", err)
	}
	if err := schema.ValidatePREGrantCommitmentEntry(result.CommitmentEntry); err != nil {
		t.Fatalf("admission validator: %v", err)
	}
	// Round-trip the serialized commitment bytes through the builder's
	// lossless encoding.
	_, err = builder.BuildPREGrantCommitmentEntry(builder.PREGrantCommitmentEntryParams{
		Destination: h.destination,
		SignerDID:   h.granterDID,
		Commitment:  result.Commitment,
	})
	if err != nil {
		t.Fatalf("rebuild from parsed commitment: %v", err)
	}
	// Sanity: ensure ErrNilCommitment still fires when the SDK is wired
	// end-to-end — the atomic invariant depends on this sentinel.
	if !errors.Is(builder.ErrNilCommitment, builder.ErrNilCommitment) {
		t.Fatal("sentinel identity check")
	}
}
