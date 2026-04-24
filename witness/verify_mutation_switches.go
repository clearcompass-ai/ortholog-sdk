// Package witness — verify_mutation_switches.go holds the ADR-005
// §6 mutation-audit switch for witness/verify.go. Declared in its
// own file so the audit-v775 runner's line-local rewrite can target
// exactly one declaration.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING muEnableWitnessQuorumCount.   │
//	├─────────────────────────────────────────────────────────────┤
//	│  This constant gates the structural pre-check inside        │
//	│  VerifyTreeHead that the supplied witness key set is large  │
//	│  enough to satisfy the requested K-of-N quorum. Setting it  │
//	│  to false permanently lets undersized witness sets slip     │
//	│  past the early gate; the underlying VerifyWitnessCosignatures │
//	│  may surface a different (less specific) error or silently  │
//	│  accept the operation depending on signature shape.         │
//	│                                                             │
//	│  Binding test:                                              │
//	│    TestWitnessQuorumCount_Binding                           │
//	└─────────────────────────────────────────────────────────────┘
package witness

// muEnableWitnessQuorumCount gates the (len(witnessKeys) < quorumK)
// pre-check inside VerifyTreeHead. When true (production), the gate
// rejects with a specific "witness set size %d < quorum %d" error
// before any cryptographic verification runs. When false, the
// pre-check is removed and undersized witness sets fall through to
// the Phase-1 primitive — which may return a less-specific error
// or silently accept the operation depending on signature shape.
const muEnableWitnessQuorumCount = true
