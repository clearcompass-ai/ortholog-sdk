// Package lifecycle — commitment_atomic.go holds the lifecycle-layer
// mutation switch gating atomic commitment-entry emission per ADR-005
// §4.
//
// Atomic emission invariant. Every lifecycle function that produces
// shares or KFrags (grantUmbralPRE, ProvisionSingleLogWithEscrow,
// StoreMappingV2) MUST return a non-nil commitment entry alongside
// the material. The invariant is structural: the return types are
// shaped such that a caller cannot extract shares/KFrags without the
// commitment entry. The mutation switch below gates the internal
// sanity assertion that enforces the invariant. In production the
// switch is always true; flipping it false is a mutation-audit
// probe that allows a path to skip the non-nil assertion, and the
// binding test catches the absence by observing that a commitment
// entry never reaches the `Result.CommitmentEntry` field.
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

// muEnableCommitmentEmissionAtomic gates the internal assertion that
// a lifecycle function returning shares/KFrags also returns a
// non-nil CommitmentEntry. Binding tests:
//
//   - TestGrantArtifactAccess_AtomicCommitmentEmission
//   - TestStoreMappingV2_AtomicCommitmentEmission
//   - TestProvisionSingleLogWithEscrow_AtomicCommitmentEmission
const muEnableCommitmentEmissionAtomic = true
