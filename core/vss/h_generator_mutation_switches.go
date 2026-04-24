// Package vss — h_generator_mutation_switches.go holds the ADR-005
// §6 mutation-audit switch for core/vss/h_generator.go. Declared in
// its own file so the audit-v775 runner's line-local rewrite can
// target exactly one declaration.
//
// Two mutation probes are registered for this file (see
// core/vss/h_generator.mutation-audit.yaml):
//
//   - muEnableHGeneratorLiftX (declared here) — bool_const. Off
//     makes liftX treat every x candidate as not-liftable, which
//     exhausts the try-and-increment loop. Binding test asserts
//     deriveHGenerator returns ErrHGeneratorExhausted when the
//     gate is off and a valid (x, y) pair when the gate is on.
//
//   - HGeneratorSeedFlip (string_mutation) — flips the v1 suffix
//     on the printable HGeneratorSeed constant. Binding test is
//     TestHGenerator_FrozenSeed, which asserts both the seed
//     constant and the frozen xy_sha256 hash; either assertion
//     fires on the mutation.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING muEnableHGeneratorLiftX. │
//	├─────────────────────────────────────────────────────────────┤
//	│  The constant gates a defensive ModSqrt + IsOnCurve pair in │
//	│  liftX. Setting it to false permanently breaks H derivation │
//	│  outright (HGenerator returns ErrHGeneratorExhausted). The  │
//	│  switch exists so the audit runner can flip it and observe  │
//	│  the binding test fires; any other use is wrong.            │
//	└─────────────────────────────────────────────────────────────┘
package vss

// muEnableHGeneratorLiftX gates the ModSqrt + IsOnCurve sequence in
// liftX. When true (production), liftX attempts to recover y from
// y² = x³ + 7 mod p and returns (y, true) on success. When false,
// liftX short-circuits to (nil, false) — every candidate x is
// treated as non-liftable, deriveHGenerator exhausts
// HGeneratorMaxAttempts, and HGenerator surfaces
// ErrHGeneratorExhausted. Binding test:
//   - TestHGenerator_LiftXGate_Binding
const muEnableHGeneratorLiftX = true
