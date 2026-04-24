// Package integration — commitment_lifecycle_pre_test.go drives the
// PRE side of Subgroup 3.7: grant → publish → fetch → verify →
// decrypt, plus tampered-commitment, tampered-SplitID, equivocation,
// and wrong-recipient negative variants.
package integration

import (
	"bytes"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/internal/testkeys"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// preGrantContext captures all the bytes the PRE integration tests
// need in scope. Reused across the positive and negative variants.
type preGrantContext struct {
	owner         testkeys.Keypair
	recipient     testkeys.Keypair
	capsule       *artifact.Capsule
	ciphertext    []byte
	artifactCID   storage.CID
	contentDigest storage.CID
	destination   string
	granterDID    string
	recipientDID  string
	plaintext     []byte
}

func newPREGrantContext(t *testing.T) *preGrantContext {
	t.Helper()
	owner := testkeys.New(t)
	recipient := testkeys.New(t)
	plaintext := []byte("phase C commitment lifecycle integration payload")
	capsule, ciphertext, err := artifact.PRE_Encrypt(owner.PK, plaintext)
	if err != nil {
		t.Fatalf("PRE_Encrypt: %v", err)
	}
	return &preGrantContext{
		owner:         owner,
		recipient:     recipient,
		capsule:       capsule,
		ciphertext:    ciphertext,
		artifactCID:   storage.Compute(ciphertext),
		contentDigest: storage.Compute(plaintext),
		destination:   "did:web:example.com:exchange",
		granterDID:    "did:web:example.com:grantor",
		recipientDID:  "did:web:example.com:recipient",
		plaintext:     plaintext,
	}
}

func (c *preGrantContext) grantParams() lifecycle.GrantArtifactAccessParams {
	return lifecycle.GrantArtifactAccessParams{
		Destination:     c.destination,
		ArtifactCID:     c.artifactCID,
		ContentDigest:   c.contentDigest,
		RecipientPubKey: c.recipient.PK,
		SchemaParams: &types.SchemaParameters{
			ArtifactEncryption:     types.EncryptionUmbralPRE,
			GrantAuthorizationMode: types.GrantAuthOpen,
			ReEncryptionThreshold:  &types.ThresholdConfig{M: 3, N: 5},
		},
		GranterDID:     c.granterDID,
		RecipientDID:   c.recipientDID,
		Capsule:        c.capsule,
		OwnerSecretKey: c.owner.SK,
	}
}

// TestPREGrantLifecycle_Integration drives the full positive cycle.
func TestPREGrantLifecycle_Integration(t *testing.T) {
	ctx := newPREGrantContext(t)
	log := newCommitmentLog()

	result, err := lifecycle.GrantArtifactAccess(ctx.grantParams())
	if err != nil {
		t.Fatalf("GrantArtifactAccess: %v", err)
	}
	if result.CommitmentEntry == nil {
		t.Fatal("atomic emission: CommitmentEntry nil")
	}

	// Admission validator.
	if err := schema.ValidatePREGrantCommitmentEntry(result.CommitmentEntry); err != nil {
		t.Fatalf("admission validator rejected commitment: %v", err)
	}
	log.Publish(t, result.CommitmentEntry)

	// Fetch via public grant context.
	fetched, err := artifact.FetchPREGrantCommitment(log, ctx.granterDID, ctx.recipientDID, ctx.artifactCID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fetched == nil {
		t.Fatal("fetched nil commitment")
	}
	if err := artifact.VerifyPREGrantCommitment(fetched, ctx.granterDID, ctx.recipientDID, ctx.artifactCID); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Parity: fetched commitment wire bytes match grantor-produced.
	want, _ := artifact.SerializePREGrantCommitment(*result.Commitment)
	got, _ := artifact.SerializePREGrantCommitment(*fetched)
	if !bytes.Equal(want, got) {
		t.Fatal("fetched commitment diverges from grantor-produced")
	}

	// Decrypt via VerifyAndDecryptArtifact with fetched commitments.
	vssCommits, err := fetched.ToVSSCommitments()
	if err != nil {
		t.Fatalf("ToVSSCommitments: %v", err)
	}
	plaintext, err := lifecycle.VerifyAndDecryptArtifact(lifecycle.VerifyAndDecryptArtifactParams{
		Ciphertext:    ctx.ciphertext,
		ArtifactCID:   ctx.artifactCID,
		ContentDigest: ctx.contentDigest,
		SchemaParams: &types.SchemaParameters{
			ArtifactEncryption: types.EncryptionUmbralPRE,
		},
		CFrags:       result.CFrags[:3],
		Capsule:      result.Capsule,
		RecipientKey: ctx.recipient.SK,
		OwnerPubKey:  ctx.owner.PK,
		Commitments:  vssCommits,
	})
	if err != nil {
		t.Fatalf("VerifyAndDecryptArtifact: %v", err)
	}
	if !bytes.Equal(plaintext, ctx.plaintext) {
		t.Fatal("decrypted plaintext mismatch")
	}
}

// TestPREGrantLifecycle_TamperedCommitments_Rejected: replacing a
// commitment point with a deterministically off-curve point fails
// the on-curve gate. We choose 0x02 || 32 zero bytes because (0, y)
// with y² = 7 has no root in F_p, so this is always off-curve.
func TestPREGrantLifecycle_TamperedCommitments_Rejected(t *testing.T) {
	ctx := newPREGrantContext(t)
	log := newCommitmentLog()

	result, err := lifecycle.GrantArtifactAccess(ctx.grantParams())
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	log.Publish(t, result.CommitmentEntry)

	fetched, err := artifact.FetchPREGrantCommitment(log, ctx.granterDID, ctx.recipientDID, ctx.artifactCID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	for i := range fetched.CommitmentSet[0] {
		fetched.CommitmentSet[0][i] = 0
	}
	fetched.CommitmentSet[0][0] = 0x02
	err = artifact.VerifyPREGrantCommitment(fetched, ctx.granterDID, ctx.recipientDID, ctx.artifactCID)
	if !errors.Is(err, artifact.ErrCommitmentPointOffCurve) {
		t.Fatalf("want ErrCommitmentPointOffCurve, got %v", err)
	}
}

// TestPREGrantLifecycle_TamperedSplitID_Rejected exercises the
// muEnableSplitIDRecomputation gate.
func TestPREGrantLifecycle_TamperedSplitID_Rejected(t *testing.T) {
	ctx := newPREGrantContext(t)
	result, err := lifecycle.GrantArtifactAccess(ctx.grantParams())
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	c := *result.Commitment
	c.SplitID[0] ^= 0x01
	if err := artifact.VerifyPREGrantCommitment(&c, ctx.granterDID, ctx.recipientDID, ctx.artifactCID); !errors.Is(err, artifact.ErrCommitmentSplitIDMismatch) {
		t.Fatalf("want ErrCommitmentSplitIDMismatch, got %v", err)
	}
}

// TestPREGrantLifecycle_EquivocationDetected: two grants for the
// same (grantor, recipient, artifact) tuple share the SAME SplitID
// (deterministic derivation) but carry distinct commitment sets. The
// fetcher surfaces ErrCommitmentEquivocation with both entries.
func TestPREGrantLifecycle_EquivocationDetected(t *testing.T) {
	ctx := newPREGrantContext(t)
	log := newCommitmentLog()

	r1, err := lifecycle.GrantArtifactAccess(ctx.grantParams())
	if err != nil {
		t.Fatalf("grant 1: %v", err)
	}
	log.Publish(t, r1.CommitmentEntry)

	r2, err := lifecycle.GrantArtifactAccess(ctx.grantParams())
	if err != nil {
		t.Fatalf("grant 2: %v", err)
	}
	log.Publish(t, r2.CommitmentEntry)

	_, err = artifact.FetchPREGrantCommitment(log, ctx.granterDID, ctx.recipientDID, ctx.artifactCID)
	if !errors.Is(err, artifact.ErrCommitmentEquivocation) {
		t.Fatalf("want ErrCommitmentEquivocation, got %v", err)
	}
	var evidence *artifact.CommitmentEquivocationError
	if !errors.As(err, &evidence) {
		t.Fatal("errors.As did not recover evidence")
	}
	if len(evidence.Entries) != 2 {
		t.Fatalf("Entries len=%d, want 2", len(evidence.Entries))
	}
}

// TestPREGrantLifecycle_WrongRecipient_Rejected pins that the
// recipient DID is bound into SplitID — verifying against an
// impostor recipient fails via the SplitID recomputation gate.
func TestPREGrantLifecycle_WrongRecipient_Rejected(t *testing.T) {
	ctx := newPREGrantContext(t)
	result, err := lifecycle.GrantArtifactAccess(ctx.grantParams())
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	err = artifact.VerifyPREGrantCommitment(
		result.Commitment, ctx.granterDID, "did:web:example.com:impostor", ctx.artifactCID,
	)
	if !errors.Is(err, artifact.ErrCommitmentSplitIDMismatch) {
		t.Fatalf("want ErrCommitmentSplitIDMismatch, got %v", err)
	}
}
