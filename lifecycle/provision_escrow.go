// Package lifecycle — provision_escrow.go wires atomic V2 escrow
// commitment emission into the provisioning path per ADR-005 §4.
//
// Scope. Plain ProvisionSingleLog in provision.go does not split
// secrets; it builds scope / delegation / schema entries. Domains
// that provision a log together with an initial V2 escrow split
// (e.g., a delegation key escrowed at log creation so recovery is
// possible on day one) use ProvisionSingleLogWithEscrow: a thin
// wrapper that invokes ProvisionSingleLog, then runs escrow.SplitV2
// on the supplied secret, and returns the shares plus the signed
// escrow-split-commitment-v1 entry atomically.
//
// Atomic-emission invariant (ADR-005 §4). When EscrowSpec is
// non-nil, ProvisionSingleLogWithEscrow either returns shares +
// commitment entry or an error. When EscrowSpec is nil, the call is
// equivalent to ProvisionSingleLog. The invariant is gated by
// muEnableCommitmentEmissionAtomic; flipping it false is the
// mutation-audit probe that exercises the "shares without commitment"
// failure mode at this layer.
package lifecycle

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

var (
	// ErrProvisionEscrowMissingSecret is returned when EscrowSpec is
	// non-nil but Secret is zero-length.
	ErrProvisionEscrowMissingSecret = errors.New(
		"lifecycle/provision: EscrowSpec.Secret must be 32 bytes",
	)

	// ErrProvisionEscrowMissingDealer is returned when EscrowSpec is
	// non-nil but DealerDID is empty. The dealer DID is bound into
	// SplitID; an empty value would collide across dealers.
	ErrProvisionEscrowMissingDealer = errors.New(
		"lifecycle/provision: EscrowSpec.DealerDID must not be empty",
	)

	// ErrProvisionEscrowInvalidThreshold is returned when M/N violate
	// 2 <= M <= N <= 255.
	ErrProvisionEscrowInvalidThreshold = errors.New(
		"lifecycle/provision: EscrowSpec threshold (M,N) invalid",
	)

	// ErrProvisionEscrowAtomicEmissionViolated is returned if the
	// atomic-emission invariant is violated at return.
	ErrProvisionEscrowAtomicEmissionViolated = errors.New(
		"lifecycle/provision: atomic emission invariant violated: shares without commitment entry",
	)
)

// ─────────────────────────────────────────────────────────────────────
// Specs
// ─────────────────────────────────────────────────────────────────────

// EscrowSpec configures an initial V2 Pedersen-VSS escrow split
// produced at log provisioning time.
type EscrowSpec struct {
	// DealerDID is the dealer DID. Bound into SplitID via
	// ComputeEscrowSplitID; must be non-empty.
	DealerDID string

	// Secret is the 32-byte secret to split. Bound to the
	// escrow.SecretSize constraint enforced by SplitV2.
	Secret []byte

	// M and N are the VSS threshold parameters. Must satisfy
	// 2 <= M <= N <= 255.
	M int
	N int

	// NonceReader optionally overrides crypto/rand for the 32-byte
	// SplitID nonce. nil means crypto/rand.
	NonceReader io.Reader
}

// ProvisionEscrowResult carries the V2 escrow split output produced
// during ProvisionSingleLogWithEscrow. Shares and CommitmentEntry
// are either both populated or neither.
type ProvisionEscrowResult struct {
	Shares          []escrow.Share
	SplitID         [32]byte
	Nonce           [32]byte
	Commitment      *escrow.EscrowSplitCommitment
	CommitmentEntry *envelope.Entry
}

// ProvisionWithEscrowResult bundles the base LogProvision output with
// the optional escrow split output.
type ProvisionWithEscrowResult struct {
	LogProvision *LogProvision
	Escrow       *ProvisionEscrowResult
}

// ─────────────────────────────────────────────────────────────────────
// ProvisionSingleLogWithEscrow
// ─────────────────────────────────────────────────────────────────────

// ProvisionSingleLogWithEscrow is the V2-aware counterpart to
// ProvisionSingleLog. It builds all the same provisioning entries
// (scope, delegations, schemas) via the plain ProvisionSingleLog
// path. When spec is non-nil, it additionally performs a V2 escrow
// split of spec.Secret and produces the escrow-split-commitment-v1
// entry atomically. When spec is nil, the atomic-emission invariant
// is trivially satisfied (no shares produced) and the Escrow field
// is nil.
//
// The commitment entry is signed by the dealer DID and bound to the
// destination carried on cfg. Receive-side verifiers re-derive the
// SplitID via ComputeEscrowSplitID(spec.DealerDID, nonce) and match
// it against the on-log commitment entry.
func ProvisionSingleLogWithEscrow(cfg SingleLogConfig, spec *EscrowSpec) (*ProvisionWithEscrowResult, error) {
	base, err := ProvisionSingleLog(cfg)
	if err != nil {
		return nil, err
	}
	result := &ProvisionWithEscrowResult{LogProvision: base}
	if spec == nil {
		return result, nil
	}

	esc, err := runEscrowSplitForProvision(cfg, spec)
	if err != nil {
		return nil, err
	}
	result.Escrow = esc

	if err := AssertAtomicEmission(len(esc.Shares), esc.CommitmentEntry); err != nil {
		return nil, ErrProvisionEscrowAtomicEmissionViolated
	}
	return result, nil
}

// runEscrowSplitForProvision executes the V2 split + commitment
// emission for ProvisionSingleLogWithEscrow. Split out to keep the
// public function body small and linear.
func runEscrowSplitForProvision(cfg SingleLogConfig, spec *EscrowSpec) (*ProvisionEscrowResult, error) {
	if err := envelope.ValidateDestination(cfg.Destination); err != nil {
		return nil, fmt.Errorf("lifecycle/provision: %w", err)
	}
	if spec.DealerDID == "" {
		return nil, ErrProvisionEscrowMissingDealer
	}
	if len(spec.Secret) != escrow.SecretSize {
		return nil, ErrProvisionEscrowMissingSecret
	}
	if spec.M < 2 || spec.N < spec.M || spec.N > 255 {
		return nil, fmt.Errorf(
			"%w: M=%d N=%d (require 2<=M<=N<=255)",
			ErrProvisionEscrowInvalidThreshold, spec.M, spec.N,
		)
	}

	// Draw a fresh 32-byte SplitID nonce.
	var nonce [32]byte
	r := spec.NonceReader
	if r == nil {
		r = rand.Reader
	}
	if _, err := io.ReadFull(r, nonce[:]); err != nil {
		return nil, fmt.Errorf("lifecycle/provision: read nonce: %w", err)
	}

	shares, commitments, splitID, err := escrow.SplitV2(
		spec.Secret, spec.M, spec.N, spec.DealerDID, nonce,
	)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/provision: SplitV2: %w", err)
	}

	commitment, err := escrow.NewEscrowSplitCommitmentFromVSS(
		splitID, spec.M, spec.N, spec.DealerDID, commitments,
	)
	if err != nil {
		escrow.ZeroizeShares(shares)
		return nil, fmt.Errorf("lifecycle/provision: build commitment: %w", err)
	}
	if err := escrow.VerifyEscrowSplitCommitment(commitment, nonce); err != nil {
		escrow.ZeroizeShares(shares)
		return nil, fmt.Errorf("lifecycle/provision: self-verify commitment: %w", err)
	}

	commitmentEntry, err := builder.BuildEscrowSplitCommitmentEntry(builder.EscrowSplitCommitmentEntryParams{
		Destination: cfg.Destination,
		SignerDID:   spec.DealerDID,
		Commitment:  commitment,
		EventTime:   cfg.EventTime,
	})
	if err != nil {
		escrow.ZeroizeShares(shares)
		return nil, fmt.Errorf("lifecycle/provision: build commitment entry: %w", err)
	}

	return &ProvisionEscrowResult{
		Shares:          shares,
		SplitID:         splitID,
		Nonce:           nonce,
		Commitment:      commitment,
		CommitmentEntry: commitmentEntry,
	}, nil
}
