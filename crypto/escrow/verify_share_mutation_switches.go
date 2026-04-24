// Package escrow — verify_share_mutation_switches.go holds the
// ADR-005 §6 mutation-audit switches for verify_share.go. Declared
// in their own file so the audit-v775 runner's line-local rewrite
// can target exactly one declaration per constant.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING ANY muEnable* CONSTANT.   │
//	├─────────────────────────────────────────────────────────────┤
//	│  These constants gate the five structural checks inside     │
//	│  validateShareFormatV1 and validateShareFormatV2. Setting   │
//	│  any of them to false permanently is a security regression  │
//	│  that lets malformed shares pass structural validation and  │
//	│  reach reconstruction — potentially with attacker-chosen    │
//	│  SplitIDs, indices, or field tags. The switches exist so    │
//	│  the audit runner can flip them and observe that the        │
//	│  binding tests fire; any other use is wrong.                │
//	│                                                             │
//	│  Binding tests (crypto/escrow/verify_share.mutation-audit.yaml):
//	│    muEnableV1FieldEmptyCheck      →                         │
//	│      TestValidateShareFormatV1_V1FieldEmpty_Binding         │
//	│    muEnableV2FieldPopulatedCheck  →                         │
//	│      TestValidateShareFormatV2_V2FieldPopulated_Binding     │
//	│    muEnableShareIndexNonZero     →                          │
//	│      TestValidateShareFormat_IndexNonZero_Binding           │
//	│    muEnableSplitIDPresent        →                          │
//	│      TestValidateShareFormat_SplitIDPresent_Binding         │
//	│    muEnableFieldTagDiscrimination →                         │
//	│      TestValidateShareFormat_FieldTagDiscrimination_Binding │
//	└─────────────────────────────────────────────────────────────┘
package escrow

// muEnableV1FieldEmptyCheck gates the V1 invariant that
// BlindingFactor and CommitmentHash (V2-only fields) MUST be zero.
// Off allows a V1 share to carry populated V2 fields — a Version-
// byte forgery path that downstream code would misinterpret.
const muEnableV1FieldEmptyCheck = true

// muEnableV2FieldPopulatedCheck gates the V2 invariant that
// BlindingFactor and CommitmentHash MUST be non-zero (Pedersen-VSS
// structural contract). Off allows a V2 share with empty V2 fields
// through — Pedersen verification would fail downstream with a
// confusing error, when the correct behaviour is a clear
// ErrV2FieldEmpty at the structural boundary.
const muEnableV2FieldPopulatedCheck = true

// muEnableShareIndexNonZero gates the (s.Index == 0) rejection.
// Applies to both V1 and V2 via their common gate path. Off admits
// index 0 — which collides with the secret position at Lagrange
// x=0 and would leak the secret's polynomial evaluation there.
const muEnableShareIndexNonZero = true

// muEnableSplitIDPresent gates the (zeroArray32(s.SplitID))
// rejection. Applies to both V1 and V2. Off admits zero SplitIDs,
// which collide across unrelated splits and defeat the cross-split
// mixing guard in VerifyShareSet.
const muEnableSplitIDPresent = true

// muEnableFieldTagDiscrimination gates the FieldTag check on each
// version path:
//
//   - V1: allows 0 (legacy) or SchemeGF256Tag; rejects other values.
//   - V2: allows 0 (legacy) or SchemePedersenTag; rejects other values.
//
// Off admits unknown field tags — including tags from future
// schemes being fed into current-scheme code, or attacker-chosen
// values meant to confuse scheme dispatch.
const muEnableFieldTagDiscrimination = true
