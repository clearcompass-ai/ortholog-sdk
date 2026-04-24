// Package verifier — cosignature_mutation_switches.go holds the
// ADR-005 §6 mutation-audit switch for verifier/cosignature.go.
// Declared in its own file so the audit-v775 runner's line-local
// rewrite can target exactly one declaration.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING muEnableCosignatureBinding. │
//	├─────────────────────────────────────────────────────────────┤
//	│  This constant gates the position-binding check inside       │
//	│  IsCosignatureOf. Setting it to false permanently is the     │
//	│  exact ORTHO-BUG-009 / BUG-015 / BUG-016 regression: a       │
//	│  cosignature on any unrelated entry gets counted as          │
//	│  "approval" of a pending operation. The AST linter           │
//	│  cmd/lint-cosignature-binding enforces that no file other    │
//	│  than cosignature.go checks CosignatureOf raw; this switch   │
//	│  gates the one canonical check the linter's design relies on.│
//	│                                                             │
//	│  Binding test:                                              │
//	│    TestIsCosignatureOf_PositionMismatch_Binding             │
//	└─────────────────────────────────────────────────────────────┘
package verifier

// muEnableCosignatureBinding gates the position-match clause inside
// IsCosignatureOf. When true (production), IsCosignatureOf returns
// true iff entry is non-nil, entry.Header.CosignatureOf is non-nil,
// AND CosignatureOf.Equal(expectedPos) is true. When false, the
// position-match clause is removed and IsCosignatureOf returns true
// for any cosignature-shaped entry regardless of which position it
// references — the exact bug class this predicate exists to close.
//
// Binding test: TestIsCosignatureOf_PositionMismatch_Binding.
const muEnableCosignatureBinding = true
