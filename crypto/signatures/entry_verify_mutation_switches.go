// Package signatures — entry_verify_mutation_switches.go holds the
// ADR-005 §6 mutation-audit switches for entry_verify.go.
// Declared in their own file so the audit-v775 runner's line-local
// rewrite can target exactly one declaration per constant.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING ANY muEnable* CONSTANT.   │
//	├─────────────────────────────────────────────────────────────┤
//	│  These constants gate the three structural checks inside    │
//	│  VerifyEntry / ParsePubKey — the entry-signature path that  │
//	│  every Ortholog log entry passes through. Setting any of    │
//	│  them to false permanently is a security regression that    │
//	│  admits malformed or off-curve inputs into ecdsa.Verify     │
//	│  (whose behaviour on invalid inputs is implementation-      │
//	│  defined). The switches exist so the audit runner can flip  │
//	│  them and observe that the binding tests fire; any other    │
//	│  use is wrong.                                              │
//	│                                                             │
//	│  Binding tests (crypto/signatures/entry_verify.mutation-audit.yaml):
//	│    muEnableEntrySignatureVerify →                           │
//	│      TestVerifyEntry_RejectsBadSignature_Binding            │
//	│    muEnablePubKeyOnCurve        →                           │
//	│      TestParsePubKey_RejectsOffCurve_Binding                │
//	│    muEnableSignatureLength      →                           │
//	│      TestVerifyEntry_RejectsBadLength_Binding               │
//	└─────────────────────────────────────────────────────────────┘
package signatures

// muEnableEntrySignatureVerify gates the ecdsa.Verify call in
// VerifyEntry. When true (production), a tampered signature
// produces ErrSignatureVerificationFailed. When false, the
// verification step is skipped and any 64-byte signature with
// non-zero R, S returns nil — silently accepting forgeries.
const muEnableEntrySignatureVerify = true

// muEnablePubKeyOnCurve gates the secp256k1.ParsePubKey error
// return inside ParsePubKey. When true, off-curve / malformed
// public-key bytes produce a wrapped parse error. When false,
// the error is suppressed; off-curve bytes return (nil, nil),
// and downstream consumers nil-deref or silently fail closed.
const muEnablePubKeyOnCurve = true

// muEnableSignatureLength gates the (len(sig) != 64) length
// check inside VerifyEntry. When true, signatures of any other
// length produce ErrInvalidRawSignatureLength. When false, the
// length check is bypassed and ecdsa.Verify is invoked on
// big-endian decodings of arbitrary-length byte slices —
// whose semantics ECDSA does not specify.
const muEnableSignatureLength = true
