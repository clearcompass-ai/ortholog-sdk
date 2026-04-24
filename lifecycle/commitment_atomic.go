// Package lifecycle — commitment_atomic.go holds the lifecycle-layer
// mutation switch gating atomic commitment-entry emission per ADR-005
// §4 and the AssertAtomicEmission helper that enforces it.
//
// Atomic emission invariant. Every lifecycle function that produces
// shares or KFrags (grantUmbralPRE, ProvisionSingleLogWithEscrow,
// StoreMappingV2) MUST return a non-nil commitment entry alongside
// the material. The invariant is structural: the return types are
// shaped such that a caller cannot extract shares/KFrags without the
// commitment entry. The mutation switch below gates the internal
// sanity assertion that enforces the invariant. In production the
// switch is always true; flipping it false is a mutation-audit
// probe that disables the assertion.
//
// Binding discipline. The assertion is extracted into
// AssertAtomicEmission so a binding test can call it directly with
// a synthetic "CFrags-without-CommitmentEntry" tuple — the pathological
// state the production happy path never produces. That makes the
// switch mutation-audit-visible: flipping it false causes the
// assertion to return nil on the bad tuple and the binding test fails.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING muEnableCommitmentEmissionAtomic. │
//	├─────────────────────────────────────────────────────────────┤
//	│  This constant is part of the v7.75 mutation-audit           │
//	│  discipline. Setting it to false permanently is a security   │
//	│  regression that readmits silent share-without-commitment    │
//	│  emission. The switch exists so the audit runner can flip it │
//	│  and observe that the binding test fires; any other use is   │
//	│  wrong. Do not change the default.                           │
//	└─────────────────────────────────────────────────────────────┘
package lifecycle

import (
	"errors"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
)

// muEnableCommitmentEmissionAtomic gates AssertAtomicEmission.
// Binding tests:
//
//   - TestAtomicEmissionInvariant_FireOnSharesWithoutCommitment
//   - TestGrantArtifactAccess_AtomicCommitmentEmission
const muEnableCommitmentEmissionAtomic = true

// ErrAtomicEmissionInvariantViolated is returned by
// AssertAtomicEmission when the supplied (cfragsOrShares,
// commitmentEntry) tuple indicates material was emitted without its
// corresponding commitment entry. The sentinel is wrapped in a more
// specific error at the call site.
var ErrAtomicEmissionInvariantViolated = errors.New(
	"lifecycle/commitment_atomic: shares/CFrags emitted without CommitmentEntry",
)

// AssertAtomicEmission enforces the ADR-005 §4 invariant: if any
// material (CFrags for PRE, Share slice for escrow) is non-empty
// then commitmentEntry MUST be non-nil. Returns nil on success,
// ErrAtomicEmissionInvariantViolated on violation.
//
// Gated by muEnableCommitmentEmissionAtomic; flipping the switch
// false makes the assertion a no-op. The binding test exercises the
// switch directly by constructing a pathological tuple and asserting
// the error fires (when the switch is true) or does not fire (when
// the switch is false — the mutation-audit probe case).
func AssertAtomicEmission(materialCount int, commitmentEntry *envelope.Entry) error {
	if !muEnableCommitmentEmissionAtomic {
		return nil
	}
	if materialCount > 0 && commitmentEntry == nil {
		return ErrAtomicEmissionInvariantViolated
	}
	return nil
}

// AssertPREAtomicEmission is the PRE-side convenience wrapper
// around AssertAtomicEmission that names the CFrag slice in its
// signature so callers at the PRE call site are self-documenting.
func AssertPREAtomicEmission(cfrags []*artifact.CFrag, commitmentEntry *envelope.Entry) error {
	return AssertAtomicEmission(len(cfrags), commitmentEntry)
}
