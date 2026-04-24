// Package integration — commitment_lifecycle_escrow_test.go drives
// the V2 escrow side of Subgroup 3.7: SplitV2 → emit commitment entry
// → publish → fetch → verify, plus tampered-SplitID and equivocation
// negative variants. ProvisionSingleLogWithEscrow threads the full
// lifecycle together.
package integration

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/vss"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
)

// TestEscrowSplitLifecycle_Integration: provision → publish → fetch
// → verify. Uses ProvisionSingleLogWithEscrow so the split,
// commitment entry, and log provisioning are produced atomically.
func TestEscrowSplitLifecycle_Integration(t *testing.T) {
	log := newCommitmentLog()

	dealer := "did:web:example.com:dealer"
	secret := make([]byte, escrow.SecretSize)
	for i := range secret {
		secret[i] = byte(i + 7)
	}
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 13)
	}

	provResult, err := lifecycle.ProvisionSingleLogWithEscrow(
		lifecycle.SingleLogConfig{
			Destination: "did:web:example.com:exchange",
			SignerDID:   "did:web:example.com:operator",
			LogDID:      "did:web:example.com:log",
			AuthoritySet: map[string]struct{}{
				"did:web:example.com:operator": {},
			},
		},
		&lifecycle.EscrowSpec{
			DealerDID:   dealer,
			Secret:      secret,
			M:           3,
			N:           5,
			NonceReader: bytes.NewReader(nonce[:]),
		},
	)
	if err != nil {
		t.Fatalf("ProvisionSingleLogWithEscrow: %v", err)
	}
	esc := provResult.Escrow
	if esc == nil || esc.CommitmentEntry == nil {
		t.Fatal("atomic emission violated")
	}

	if err := schema.ValidateEscrowSplitCommitmentEntry(esc.CommitmentEntry); err != nil {
		t.Fatalf("admission validator: %v", err)
	}
	log.Publish(t, esc.CommitmentEntry)

	fetched, err := escrow.FetchEscrowSplitCommitment(log, esc.SplitID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fetched == nil {
		t.Fatal("fetched nil commitment")
	}
	if err := escrow.VerifyEscrowSplitCommitment(fetched, esc.Nonce); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if fetched.DealerDID != dealer {
		t.Fatalf("DealerDID drift: %q", fetched.DealerDID)
	}

	// Wire-level parity.
	a, _ := escrow.SerializeEscrowSplitCommitment(*esc.Commitment)
	b, _ := escrow.SerializeEscrowSplitCommitment(*fetched)
	if !bytes.Equal(a, b) {
		t.Fatal("fetched escrow commitment diverges from provision output")
	}
}

// TestEscrowSplitLifecycle_TamperedSplitID_Rejected covers the
// muEnableEscrowSplitIDRecomputation gate.
func TestEscrowSplitLifecycle_TamperedSplitID_Rejected(t *testing.T) {
	dealer := "did:web:example.com:dealer"
	secret := make([]byte, escrow.SecretSize)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 2)
	}
	_, commitments, splitID, err := escrow.SplitV2(secret, 3, 5, dealer, nonce)
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}
	esc, err := escrow.NewEscrowSplitCommitmentFromVSS(splitID, 3, 5, dealer, commitments)
	if err != nil {
		t.Fatalf("NewEscrowSplitCommitmentFromVSS: %v", err)
	}
	esc.SplitID[0] ^= 0x01
	if err := escrow.VerifyEscrowSplitCommitment(esc, nonce); !errors.Is(err, escrow.ErrEscrowCommitmentSplitIDMismatch) {
		t.Fatalf("want ErrEscrowCommitmentSplitIDMismatch, got %v", err)
	}
}

// TestEscrowSplitLifecycle_EquivocationDetected publishes two
// distinct commitments for the same SplitID and confirms the
// fetcher surfaces ErrEscrowCommitmentEquivocation.
func TestEscrowSplitLifecycle_EquivocationDetected(t *testing.T) {
	log := newCommitmentLog()
	dealer := "did:web:example.com:dealer"
	secret := make([]byte, escrow.SecretSize)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 2)
	}

	_, commits1, splitID, err := escrow.SplitV2(secret, 3, 5, dealer, nonce)
	if err != nil {
		t.Fatalf("SplitV2 #1: %v", err)
	}
	_, commits2, splitID2, err := escrow.SplitV2(secret, 3, 5, dealer, nonce)
	if err != nil {
		t.Fatalf("SplitV2 #2: %v", err)
	}
	if splitID != splitID2 {
		t.Fatal("same dealer+nonce produced different SplitIDs")
	}

	for _, c := range []vss.Commitments{commits1, commits2} {
		cmt, err := escrow.NewEscrowSplitCommitmentFromVSS(splitID, 3, 5, dealer, c)
		if err != nil {
			t.Fatalf("NewEscrowSplitCommitmentFromVSS: %v", err)
		}
		raw, err := escrow.SerializeEscrowSplitCommitment(*cmt)
		if err != nil {
			t.Fatalf("Serialize: %v", err)
		}
		payload, err := json.Marshal(map[string]any{
			"schema_id":            escrow.EscrowSplitCommitmentSchemaID,
			"commitment_bytes_hex": hex.EncodeToString(raw),
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
			SignerDID:   dealer,
			Destination: "did:web:example.com:exchange",
		}, payload)
		if err != nil {
			t.Fatalf("NewUnsignedEntry: %v", err)
		}
		log.Publish(t, entry)
	}

	_, err = escrow.FetchEscrowSplitCommitment(log, splitID)
	if !errors.Is(err, escrow.ErrEscrowCommitmentEquivocation) {
		t.Fatalf("want ErrEscrowCommitmentEquivocation, got %v", err)
	}
}
