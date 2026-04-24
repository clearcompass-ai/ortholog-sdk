// Package vss — pedersen_mutation_switches.go holds the ADR-005 §6
// mutation-audit switches for core/vss/pedersen.go. Declared in
// their own file so the audit-v775 runner's line-local rewrite can
// target exactly one declaration per constant.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING ANY muEnable* CONSTANT.   │
//	├─────────────────────────────────────────────────────────────┤
//	│  These constants gate defensive checks inside VerifyPoints  │
//	│  — the point-level Pedersen polynomial-consistency check    │
//	│  that pre.go's checkPedersen delegates to. Setting any of   │
//	│  them to false permanently is a security regression that    │
//	│  lets malformed inputs reach curve arithmetic. The switches │
//	│  exist so the audit runner can flip them and observe that   │
//	│  the binding tests fire; any other use is wrong.            │
//	│                                                             │
//	│  Binding tests (see core/vss/pedersen.mutation-audit.yaml): │
//	│    muEnablePedersenIndexBounds  →                           │
//	│      TestVerifyPoints_RejectsIndexZero_Binding              │
//	│      TestVerifyPoints_RejectsIndexOverMax_Binding           │
//	│    muEnablePedersenOnCurveCheck →                           │
//	│      TestVerifyPoints_RejectsOffCurveVK_Binding             │
//	│      TestVerifyPoints_RejectsOffCurveBK_Binding             │
//	└─────────────────────────────────────────────────────────────┘
package vss

// muEnablePedersenIndexBounds gates the (index == 0 || index >
// MaxShares) rejection in VerifyPoints. Off accepts an index of 0
// (which collides with the secret position in Lagrange interpolation
// at x = 0) or indices above the 255 share cap.
const muEnablePedersenIndexBounds = true

// muEnablePedersenOnCurveCheck gates the belt-and-braces IsOnCurve
// validation of the (vk, bk) point pair inside VerifyPoints. Off
// allows off-curve inputs to reach curve.Add, whose behavior on
// off-curve arguments is undefined — and on stdlib secp256k1 tends
// to produce on-curve outputs for off-curve inputs, so a downstream
// equation match is possible for attacker-chosen (vk, bk).
const muEnablePedersenOnCurveCheck = true
