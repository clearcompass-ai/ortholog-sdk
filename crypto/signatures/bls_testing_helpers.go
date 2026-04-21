/*
FILE PATH:

	crypto/signatures/bls_testing_helpers.go

DESCRIPTION:

	Test-only helpers shared across the BLS test files. Exists because
	the test fixtures in bls_verifier_test.go, bls_pop_test.go, and
	bls_rogue_key_test.go all need to cast between the gnark Fr type
	and interface{} (the fixture uses interface{} to avoid leaking the
	gnark type into exported test-struct field types).

	This file has the _test.go suffix so it is compiled only into test
	binaries, never into production artifacts.

	The coerceFr helper provides a single choke point for the type
	assertion. Centralizing it here avoids scattering duplicate
	assertions across test files and makes any future refactor of the
	fixture type surface a single-file change.
*/
package signatures

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// coerceFr extracts an *fr.Element from an interface{} value produced
// by test fixtures that store private keys as interface{} to keep
// fixture structs free of gnark-crypto types in their declarations.
//
// Panics on type mismatch. This is deliberate: a fixture that stores
// a non-*fr.Element in the private-key slot is a programming error in
// the test, not a runtime condition to handle gracefully.
func coerceFr(v interface{}) *fr.Element {
	if v == nil {
		panic("coerceFr: nil value")
	}
	fr, ok := v.(*fr.Element)
	if !ok {
		panic("coerceFr: value is not *fr.Element")
	}
	return fr
}
