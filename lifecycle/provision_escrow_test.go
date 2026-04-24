package lifecycle

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// baseCfg returns a valid SingleLogConfig that ProvisionSingleLog
// accepts without error.
func baseCfg() SingleLogConfig {
	return SingleLogConfig{
		Destination: "did:web:example.com:exchange",
		SignerDID:   "did:web:example.com:operator",
		LogDID:      "did:web:example.com:log",
		AuthoritySet: map[string]struct{}{
			"did:web:example.com:operator": {},
		},
		Schemas: []SchemaSpec{
			{Parameters: types.SchemaParameters{}},
		},
		EventTime: 1700000000,
	}
}

func baseSecret() []byte {
	s := make([]byte, escrow.SecretSize)
	for i := range s {
		s[i] = byte(i + 1)
	}
	return s
}

// ─────────────────────────────────────────────────────────────────────
// Nil EscrowSpec = plain provisioning
// ─────────────────────────────────────────────────────────────────────

// TestProvisionSingleLogWithEscrow_NilSpec_IsEquivalentToPlain pins
// that omitting EscrowSpec produces the plain LogProvision with no
// Escrow field — the atomic-emission invariant trivially holds (no
// shares produced).
func TestProvisionSingleLogWithEscrow_NilSpec_IsEquivalentToPlain(t *testing.T) {
	result, err := ProvisionSingleLogWithEscrow(baseCfg(), nil)
	if err != nil {
		t.Fatalf("ProvisionSingleLogWithEscrow: %v", err)
	}
	if result.Escrow != nil {
		t.Fatal("Escrow field must be nil when spec is nil")
	}
	if result.LogProvision == nil || result.LogProvision.ScopeEntry == nil {
		t.Fatal("plain provisioning did not produce scope entry")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Atomic emission happy path
// ─────────────────────────────────────────────────────────────────────

func TestProvisionSingleLogWithEscrow_AtomicCommitmentEmission(t *testing.T) {
	spec := &EscrowSpec{
		DealerDID: "did:web:example.com:dealer",
		Secret:    baseSecret(),
		M:         3,
		N:         5,
	}
	result, err := ProvisionSingleLogWithEscrow(baseCfg(), spec)
	if err != nil {
		t.Fatalf("ProvisionSingleLogWithEscrow: %v", err)
	}
	if result.Escrow == nil {
		t.Fatal("Escrow nil")
	}
	esc := result.Escrow
	if len(esc.Shares) != 5 {
		t.Fatalf("shares=%d want 5", len(esc.Shares))
	}
	if esc.CommitmentEntry == nil {
		t.Fatal("CommitmentEntry must be non-nil (atomic emission violated)")
	}
	if esc.Commitment == nil {
		t.Fatal("Commitment must be non-nil")
	}

	// Admission validator accepts the entry.
	if err := schema.ValidateEscrowSplitCommitmentEntry(esc.CommitmentEntry); err != nil {
		t.Fatalf("admission validator: %v", err)
	}

	// SplitID binds to (dealer, nonce).
	want := escrow.ComputeEscrowSplitID(spec.DealerDID, esc.Nonce)
	if esc.SplitID != want {
		t.Fatalf("SplitID drift")
	}
	if err := escrow.VerifyEscrowSplitCommitment(esc.Commitment, esc.Nonce); err != nil {
		t.Fatalf("commitment does not verify: %v", err)
	}

	// Destination bound into the entry.
	if esc.CommitmentEntry.Header.Destination != baseCfg().Destination {
		t.Fatalf("destination drift: %q", esc.CommitmentEntry.Header.Destination)
	}
	if esc.CommitmentEntry.Header.SignerDID != spec.DealerDID {
		t.Fatalf("SignerDID drift: %q", esc.CommitmentEntry.Header.SignerDID)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Negative paths
// ─────────────────────────────────────────────────────────────────────

func TestProvisionSingleLogWithEscrow_RejectsEmptyDealer(t *testing.T) {
	spec := &EscrowSpec{DealerDID: "", Secret: baseSecret(), M: 3, N: 5}
	_, err := ProvisionSingleLogWithEscrow(baseCfg(), spec)
	if !errors.Is(err, ErrProvisionEscrowMissingDealer) {
		t.Fatalf("want ErrProvisionEscrowMissingDealer, got %v", err)
	}
}

func TestProvisionSingleLogWithEscrow_RejectsShortSecret(t *testing.T) {
	spec := &EscrowSpec{DealerDID: "did:web:x", Secret: []byte{1, 2, 3}, M: 3, N: 5}
	_, err := ProvisionSingleLogWithEscrow(baseCfg(), spec)
	if !errors.Is(err, ErrProvisionEscrowMissingSecret) {
		t.Fatalf("want ErrProvisionEscrowMissingSecret, got %v", err)
	}
}

func TestProvisionSingleLogWithEscrow_RejectsBadThreshold(t *testing.T) {
	spec := &EscrowSpec{DealerDID: "did:web:x", Secret: baseSecret(), M: 5, N: 3}
	_, err := ProvisionSingleLogWithEscrow(baseCfg(), spec)
	if !errors.Is(err, ErrProvisionEscrowInvalidThreshold) {
		t.Fatalf("want ErrProvisionEscrowInvalidThreshold, got %v", err)
	}
}

func TestProvisionSingleLogWithEscrow_RejectsBadDestination(t *testing.T) {
	spec := &EscrowSpec{DealerDID: "did:web:x", Secret: baseSecret(), M: 3, N: 5}
	cfg := baseCfg()
	cfg.Destination = "" // breaks validation at plain ProvisionSingleLog
	_, err := ProvisionSingleLogWithEscrow(cfg, spec)
	if err == nil {
		t.Fatal("want error on empty destination, got nil")
	}
}
