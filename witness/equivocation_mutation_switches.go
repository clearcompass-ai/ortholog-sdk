// Package witness — equivocation_mutation_switches.go holds the
// ADR-005 §6 mutation-audit switch for witness/equivocation.go.
// Declared in its own file so the audit-v775 runner's line-local
// rewrite can target exactly one declaration.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING muEnableEquivocationDetection. │
//	├─────────────────────────────────────────────────────────────┤
//	│  This constant gates the same-size, different-roots branch  │
//	│  inside DetectEquivocation — the only path that produces an │
//	│  EquivocationProof. Setting it to false permanently makes   │
//	│  every two-head comparison return (nil, nil), so the        │
//	│  monitoring layer never sees evidence of operator forks.    │
//	│                                                             │
//	│  Binding test:                                              │
//	│    TestEquivocationDetection_Binding                        │
//	└─────────────────────────────────────────────────────────────┘
package witness

// muEnableEquivocationDetection gates the post-equality branch
// inside DetectEquivocation that produces an EquivocationProof
// when two heads have the same TreeSize but different RootHash
// values and both verify under the witness quorum. When false,
// the function returns (nil, nil) for every same-size head pair
// regardless of root divergence — readmitting silent acceptance
// of operator forks.
const muEnableEquivocationDetection = true
