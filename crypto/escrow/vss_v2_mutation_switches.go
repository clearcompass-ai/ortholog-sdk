// Package escrow — vss_v2_mutation_switches.go holds the ADR-005
// §6 mutation-audit switches for vss_v2.go. Declared in their own
// file so the audit-v775 runner's line-local rewrite can target
// exactly one declaration per constant.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING ANY muEnable* CONSTANT.   │
//	├─────────────────────────────────────────────────────────────┤
//	│  These constants gate the five V2 boundary checks inside    │
//	│  splitV2WithReader and ReconstructV2. Setting any of them   │
//	│  to false permanently is a security regression that lets    │
//	│  malformed splits produce on-log commitments for invalid    │
//	│  inputs, or lets attacker-substituted shares reconstruct    │
//	│  a wrong secret. The switches exist so the audit runner     │
//	│  can flip them and observe that the binding tests fire;     │
//	│  any other use is wrong.                                    │
//	│                                                             │
//	│  Binding tests (crypto/escrow/vss_v2.mutation-audit.yaml):  │
//	│    muEnableEscrowSecretSizeCheck          →                 │
//	│      TestSplitV2_SecretSizeBinding                          │
//	│    muEnableEscrowDealerDIDNonEmpty        →                 │
//	│      TestSplitV2_DealerDIDBinding                           │
//	│    muEnableEscrowThresholdBounds          →                 │
//	│      TestSplitV2_ThresholdBoundsBinding                     │
//	│    muEnableReconstructVersionCheck        →                 │
//	│      TestReconstructV2_VersionCheckBinding                  │
//	│    muEnableReconstructShareVerification   →                 │
//	│      TestReconstructV2_ShareVerificationBinding             │
//	└─────────────────────────────────────────────────────────────┘
package escrow

// muEnableEscrowSecretSizeCheck gates the (len(secret) != SecretSize)
// structural check in splitV2WithReader. Off admits secrets of the
// wrong length; the subsequent `copy(secretArr[:], secret)` would
// silently truncate or zero-pad, producing a split that reconstructs
// a different secret than the caller intended.
const muEnableEscrowSecretSizeCheck = true

// muEnableEscrowDealerDIDNonEmpty gates the (dealerDID == "")
// structural check. Off admits an empty dealerDID into
// ComputeEscrowSplitID, producing a SplitID that collides across
// every dealer — defeating the dealer-scoped equivocation
// detection on the lifecycle layer.
const muEnableEscrowDealerDIDNonEmpty = true

// muEnableEscrowThresholdBounds gates the (M, N) bounds check:
// M >= 2, N >= M, N <= 255. Off admits degenerate (1-of-N copy)
// splits, inverted (M > N) splits, or oversized (N > 255) splits.
const muEnableEscrowThresholdBounds = true

// muEnableReconstructVersionCheck gates the ReconstructV2 assertion
// that shares[0].Version == VersionV2. Off admits a V1 share set
// into the V2 reconstruction path; the downstream Pedersen check
// would fail with a confusing error, when the correct behaviour
// is ErrUnsupportedVersion at the boundary.
const muEnableReconstructVersionCheck = true

// muEnableReconstructShareVerification gates the per-share
// VerifyShareAgainstCommitments loop inside ReconstructV2. This
// is the load-bearing V2 property: substituted, cross-split, or
// blinding-mangled shares MUST fail Pedersen verification before
// Lagrange combines them into a silently-wrong secret. Off
// readmits the silent-wrong-secret failure mode that V2 exists
// to close.
const muEnableReconstructShareVerification = true
