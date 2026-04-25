// Package smt — verify_mutation_switches.go holds the ADR-005 §6
// mutation-audit switches for verify.go. Declared in their own
// file so the audit-v775 runner's line-local rewrite can target
// exactly one declaration per constant.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING ANY muEnable* CONSTANT.   │
//	├─────────────────────────────────────────────────────────────┤
//	│  These constants gate the three structural checks SMT proof │
//	│  verification depends on. Setting any to false permanently  │
//	│  breaks the cryptographic guarantee SMT verification        │
//	│  exists to provide: that proofs reconstruct to the supplied │
//	│  root iff the leaf data is consistent with the published    │
//	│  state. The switches exist so the audit runner can flip     │
//	│  them and observe that the binding tests fire; any other    │
//	│  use is wrong.                                              │
//	│                                                             │
//	│  Binding tests (core/smt/verify.mutation-audit.yaml):       │
//	│    muEnableRootMatch             →                          │
//	│      TestVerifyMembershipProof_RejectsWrongRoot_Binding     │
//	│    muEnableProofDepthBounds      →                          │
//	│      TestVerifyMembershipProof_RejectsOversizeSiblings_Binding │
//	│    muEnableEmptyLeafDistinction  →                          │
//	│      TestVerifyNonMembershipProof_RejectsLeafPresent_Binding │
//	└─────────────────────────────────────────────────────────────┘
package smt

// muEnableRootMatch gates the (computed != root) comparison
// inside VerifyMembershipProof, VerifyNonMembershipProof,
// VerifyBatchProof, and VerifyMerkleInclusion. Off makes every
// proof silently accept regardless of whether the reconstructed
// root matches — the failure mode SMT verification exists to
// prevent.
const muEnableRootMatch = true

// muEnableProofDepthBounds gates the assertion that proof.Siblings
// has at most TreeDepth entries. A malicious prover stuffing the
// map with bit indices >= TreeDepth has no effect on the loop
// (which iterates exactly TreeDepth steps), but the silent drop
// is detection-evading; the gate surfaces stuffed proofs as
// explicit rejections.
const muEnableProofDepthBounds = true

// muEnableEmptyLeafDistinction gates the (proof.Leaf == nil) and
// (proof.Leaf != nil) checks that distinguish membership proofs
// from non-membership proofs. Off lets a non-membership proof
// pose as a membership proof (or vice versa), admitting forged
// inclusion claims for absent leaves.
const muEnableEmptyLeafDistinction = true
