// Package main implements wave1-closeout, an AST-based patch tool that
// applies the eight Wave 1 closeout items identified by review.
//
// USAGE:
//
//	cd ~/workspace/ortholog-sdk
//	go run ./cmd/wave1-closeout
//
// Output: a per-file report of what was changed, a list of any items
// that could not be mutated (with reasons), and exit code 0 if all
// planned mutations applied cleanly.
//
// The tool is IDEMPOTENT. Running it twice produces the same file
// state. Every mutation is preceded by a precondition check: if the
// file is already in the post-patch state, that item is reported as
// "already applied" and skipped.
//
// ═════════════════════════════════════════════════════════════════════
// THE EIGHT ITEMS
// ═════════════════════════════════════════════════════════════════════
//
// Item 1: Remove `var _ = fr.Element{}` no-op and the now-unused
//
//	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr" import
//	from crypto/signatures/bls_gaps_test.go.
//
// Item 2: Remove `var _ = rand.Reader` no-op and the now-unused
//
//	"crypto/rand" import from crypto/signatures/bls_signer.go.
//
// Item 3: Split TestSchemeECDSA_Value — remove the dead
//
//	`if SchemeECDSA == 0x00` branch. Add a new
//	TestSchemeValues_NonZero that locks the distinct property
//	"no scheme tag is zero" as a separate concern.
//
// Item 4: Change `t.Logf` to `t.Errorf` in
//
//	TestVerifyWitnessCosignatures_ECDSAHead_DoesNotConsultBLSVerifier.
//
// Item 5: Remove the `pubKeyID[31] = byte(i)` byte-overwrite in the
//
//	same test. Match the convention in witness_verify_test.go
//	(plain `copy(pubKeyID[:], pubBytes[:32])`).
//
// Item 6: Rewrite the file-header docstring paragraph 3 of
//
//	bls_gaps_test.go to describe raw-coordinate construction
//	(not the cofactor-multiplication plan that was abandoned).
//
// Item 7: Fix the mismatch between BLSPoPDomainTag's docstring and
//
//	its actual value. This requires reading the file to
//	determine which spelling is truth, then aligning docstring
//	or constant accordingly.
//
// Item 8: Mutation probe verification. Not a code edit — instead we
//
//	verify that the probe was run (by checking for a marker
//	file the operator creates) OR we print the exact probe
//	instructions for the operator to execute.
//
// ═════════════════════════════════════════════════════════════════════
// DESIGN
// ═════════════════════════════════════════════════════════════════════
//
// Each item is an independent Mutation function. Each Mutation:
//
//   - Takes a parsed *ast.File and the file path
//   - Returns (mutated bool, err error)
//   - Is idempotent: if already applied, returns (false, nil) with a
//     "already applied" log line, not an error
//
// The top-level runner parses each target file once, runs all
// applicable mutations, and if any returned mutated=true, formats
// and writes the file back to disk.
//
// Writes go through `go/format.Source` so the output is valid,
// gofmt-clean Go. No hand-rolled formatting.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

const (
	blsSignerPath   = "crypto/signatures/bls_signer.go"
	blsGapsTestPath = "crypto/signatures/bls_gaps_test.go"
)

// MutationResult captures the outcome of a single item.
type MutationResult struct {
	Item     int
	Name     string
	Path     string
	Changed  bool
	Skipped  bool
	SkipNote string
	Err      error
}

// ══════════════════════════════════════════════════════════════════════
// Main orchestration
// ══════════════════════════════════════════════════════════════════════

func main() {
	dryRun := flag.Bool("dry-run", false, "print what would change without writing")
	flag.Parse()

	results := []MutationResult{}

	// Parse both target files once.
	gapsFset, gapsFile, err := parseFile(blsGapsTestPath)
	if err != nil {
		die("parse %s: %v", blsGapsTestPath, err)
	}
	signerFset, signerFile, err := parseFile(blsSignerPath)
	if err != nil {
		die("parse %s: %v", blsSignerPath, err)
	}

	// Track whether each file needs a rewrite at the end.
	gapsChanged := false
	signerChanged := false

	// ──────────────────────────────────────────────────────────────
	// Items targeting bls_gaps_test.go
	// ──────────────────────────────────────────────────────────────

	// Item 1: remove var _ = fr.Element{} + fr import
	r := item1_RemoveFrScar(gapsFile)
	r.Path = blsGapsTestPath
	results = append(results, r)
	if r.Changed {
		gapsChanged = true
	}

	// Item 3: split TestSchemeECDSA_Value into _Value + _NonZero
	r = item3_SplitSchemeECDSAValue(gapsFile)
	r.Path = blsGapsTestPath
	results = append(results, r)
	if r.Changed {
		gapsChanged = true
	}

	// Item 4: t.Logf → t.Errorf in dispatch isolation test
	r = item4_LogfToErrorf(gapsFile)
	r.Path = blsGapsTestPath
	results = append(results, r)
	if r.Changed {
		gapsChanged = true
	}

	// Item 5: remove pubKeyID[31] = byte(i) byte-overwrite
	r = item5_RemovePubKeyIDByteOverwrite(gapsFile)
	r.Path = blsGapsTestPath
	results = append(results, r)
	if r.Changed {
		gapsChanged = true
	}

	// Item 6: update file-header docstring paragraph 3
	r = item6_FixFileHeaderDocstring(gapsFset, gapsFile)
	r.Path = blsGapsTestPath
	results = append(results, r)
	if r.Changed {
		gapsChanged = true
	}

	// ──────────────────────────────────────────────────────────────
	// Items targeting bls_signer.go
	// ──────────────────────────────────────────────────────────────

	// Item 2: remove var _ = rand.Reader + rand import
	r = item2_RemoveRandScar(signerFile)
	r.Path = blsSignerPath
	results = append(results, r)
	if r.Changed {
		signerChanged = true
	}

	// Item 7: align BLSPoPDomainTag docstring with actual value
	r = item7_AlignPoPDocstring(signerFset, signerFile)
	r.Path = blsSignerPath
	results = append(results, r)
	if r.Changed {
		signerChanged = true
	}

	// Item 8: mutation probe — not a code change, but a verification step
	r = item8_MutationProbeReminder()
	results = append(results, r)

	// ──────────────────────────────────────────────────────────────
	// Write files if any changes were made
	// ──────────────────────────────────────────────────────────────

	if gapsChanged {
		if err := writeFile(gapsFset, gapsFile, blsGapsTestPath, *dryRun); err != nil {
			die("write %s: %v", blsGapsTestPath, err)
		}
	}
	if signerChanged {
		if err := writeFile(signerFset, signerFile, blsSignerPath, *dryRun); err != nil {
			die("write %s: %v", blsSignerPath, err)
		}
	}

	// ──────────────────────────────────────────────────────────────
	// Report
	// ──────────────────────────────────────────────────────────────

	fmt.Println()
	fmt.Println("═════════════════════════════════════════════════════════════════════")
	fmt.Println("Wave 1 Closeout — AST Patch Report")
	fmt.Println("═════════════════════════════════════════════════════════════════════")

	anyErr := false
	for _, r := range results {
		symbol := "✓"
		status := "applied"
		switch {
		case r.Err != nil:
			symbol = "✗"
			status = "ERROR: " + r.Err.Error()
			anyErr = true
		case r.Skipped:
			symbol = "○"
			status = "skipped: " + r.SkipNote
		case !r.Changed:
			symbol = "•"
			status = "already applied (no change needed)"
		}
		fmt.Printf("  %s  Item %d (%s)\n        %s\n", symbol, r.Item, r.Name, status)
	}

	fmt.Println()
	if *dryRun {
		fmt.Println("DRY RUN — no files were written.")
	}
	if anyErr {
		os.Exit(2)
	}
}

// ══════════════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════════════

func parseFile(path string) (*token.FileSet, *ast.File, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	return fset, f, err
}

func writeFile(fset *token.FileSet, f *ast.File, path string, dryRun bool) error {
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, f); err != nil {
		return err
	}
	if dryRun {
		fmt.Printf("--- would write %s (%d bytes) ---\n", path, buf.Len())
		return nil
	}
	abs, _ := filepath.Abs(path)
	return os.WriteFile(abs, buf.Bytes(), 0o644)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "wave1-closeout: "+format+"\n", args...)
	os.Exit(1)
}

// removeImport removes an import matching the given path from the
// file's import declarations. Returns true if an import was removed.
func removeImport(f *ast.File, importPath string) bool {
	quoted := `"` + importPath + `"`
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.IMPORT {
			continue
		}
		for i, spec := range gen.Specs {
			imp := spec.(*ast.ImportSpec)
			if imp.Path.Value == quoted {
				gen.Specs = append(gen.Specs[:i], gen.Specs[i+1:]...)
				// Also update the file-level Imports slice.
				for j, fi := range f.Imports {
					if fi == imp {
						f.Imports = append(f.Imports[:j], f.Imports[j+1:]...)
						break
					}
				}
				return true
			}
		}
	}
	return false
}

// removeTopLevelVarDecl removes a top-level `var _ = <selectorExpr>`
// declaration whose RHS is a selector expression matching pkg.Name.
// Returns true if removed. The exprKind argument is "literal" for
// composite literals like fr.Element{} and "selector" for selectors
// like rand.Reader.
func removeTopLevelUnderscoreVar(f *ast.File, pkg, name, exprKind string) bool {
	for i, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		if len(gen.Specs) != 1 {
			continue
		}
		vs, ok := gen.Specs[0].(*ast.ValueSpec)
		if !ok {
			continue
		}
		if len(vs.Names) != 1 || vs.Names[0].Name != "_" {
			continue
		}
		if len(vs.Values) != 1 {
			continue
		}

		matched := false
		switch exprKind {
		case "literal":
			// `fr.Element{}` is a CompositeLit with Type SelectorExpr
			if cl, ok := vs.Values[0].(*ast.CompositeLit); ok {
				if sel, ok := cl.Type.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok {
						if ident.Name == pkg && sel.Sel.Name == name {
							matched = true
						}
					}
				}
			}
		case "selector":
			// `rand.Reader` is a bare SelectorExpr
			if sel, ok := vs.Values[0].(*ast.SelectorExpr); ok {
				if ident, ok := sel.X.(*ast.Ident); ok {
					if ident.Name == pkg && sel.Sel.Name == name {
						matched = true
					}
				}
			}
		}

		if matched {
			f.Decls = append(f.Decls[:i], f.Decls[i+1:]...)
			return true
		}
	}
	return false
}

// findFuncDecl returns the FuncDecl with the given name, or nil.
func findFuncDecl(f *ast.File, name string) *ast.FuncDecl {
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == name {
			return fd
		}
	}
	return nil
}

// findConstSpec returns the ValueSpec for a top-level const with the
// given name, or nil.
func findConstSpec(f *ast.File, name string) *ast.ValueSpec {
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			if vs, ok := spec.(*ast.ValueSpec); ok {
				for _, n := range vs.Names {
					if n.Name == name {
						return vs
					}
				}
			}
		}
	}
	return nil
}

// ══════════════════════════════════════════════════════════════════════
// Item 1: Remove fr.Element{} scar in bls_gaps_test.go
// ══════════════════════════════════════════════════════════════════════

func item1_RemoveFrScar(f *ast.File) MutationResult {
	result := MutationResult{Item: 1, Name: "Remove fr scar tissue (bls_gaps_test.go)"}

	removedVar := removeTopLevelUnderscoreVar(f, "fr", "Element", "literal")
	removedImp := removeImport(f, "github.com/consensys/gnark-crypto/ecc/bls12-381/fr")

	if !removedVar && !removedImp {
		result.Skipped = true
		result.SkipNote = "neither the var nor the import was present"
		return result
	}
	result.Changed = true
	return result
}

// ══════════════════════════════════════════════════════════════════════
// Item 2: Remove rand.Reader scar in bls_signer.go
// ══════════════════════════════════════════════════════════════════════

func item2_RemoveRandScar(f *ast.File) MutationResult {
	result := MutationResult{Item: 2, Name: "Remove rand scar tissue (bls_signer.go)"}

	removedVar := removeTopLevelUnderscoreVar(f, "rand", "Reader", "selector")
	removedImp := removeImport(f, "crypto/rand")

	if !removedVar && !removedImp {
		result.Skipped = true
		result.SkipNote = "neither the var nor the import was present"
		return result
	}
	result.Changed = true
	return result
}

// ══════════════════════════════════════════════════════════════════════
// Item 3: Split TestSchemeECDSA_Value — remove dead branch,
//         add TestSchemeValues_NonZero
// ══════════════════════════════════════════════════════════════════════

func item3_SplitSchemeECDSAValue(f *ast.File) MutationResult {
	result := MutationResult{Item: 3, Name: "Split TestSchemeECDSA_Value, remove dead branch"}

	target := findFuncDecl(f, "TestSchemeECDSA_Value")
	if target == nil {
		result.Err = fmt.Errorf("TestSchemeECDSA_Value not found")
		return result
	}

	// Find and remove the dead `if SchemeECDSA == 0x00 { t.Fatal(...) }` branch.
	// It's an IfStmt whose Cond is a BinaryExpr `SchemeECDSA == 0x00`.
	removedDeadBranch := false
	newStmts := []ast.Stmt{}
	for _, stmt := range target.Body.List {
		if ifStmt, ok := stmt.(*ast.IfStmt); ok && isSchemeEqualsZeroCheck(ifStmt) {
			removedDeadBranch = true
			continue
		}
		newStmts = append(newStmts, stmt)
	}

	// Check if TestSchemeValues_NonZero already exists.
	nonZeroExists := findFuncDecl(f, "TestSchemeValues_NonZero") != nil

	if !removedDeadBranch && nonZeroExists {
		result.Skipped = true
		result.SkipNote = "dead branch already removed and _NonZero test already present"
		return result
	}

	if removedDeadBranch {
		target.Body.List = newStmts
	}

	// Add the new TestSchemeValues_NonZero function if not present.
	if !nonZeroExists {
		newFunc := buildSchemeValuesNonZeroFunc()
		f.Decls = append(f.Decls, newFunc)
	}

	result.Changed = true
	return result
}

// isSchemeEqualsZeroCheck tests whether an IfStmt matches the dead
// branch pattern: `if SchemeECDSA == 0x00 { ... }` or
// `if SchemeBLS == 0x00 { ... }`.
func isSchemeEqualsZeroCheck(ifStmt *ast.IfStmt) bool {
	bin, ok := ifStmt.Cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return false
	}
	lhs, ok := bin.X.(*ast.Ident)
	if !ok {
		return false
	}
	if lhs.Name != "SchemeECDSA" && lhs.Name != "SchemeBLS" {
		return false
	}
	rhs, ok := bin.Y.(*ast.BasicLit)
	if !ok {
		return false
	}
	return rhs.Value == "0x00" || rhs.Value == "0"
}

// buildSchemeValuesNonZeroFunc constructs the new TestSchemeValues_NonZero
// function declaration. It's built via AST primitives rather than
// parsed from a template string to keep the tool's dependencies clean
// and the construction reviewable.
func buildSchemeValuesNonZeroFunc() *ast.FuncDecl {
	// Use parser.ParseFile on a template for clarity. Parsing a small
	// source snippet is more readable than hand-building every AST node.
	src := `package signatures

// TestSchemeValues_NonZero locks the invariant that no scheme tag
// uses the zero value. Wave 2 reserves SchemeTag == 0x00 to mean
// "scheme not declared" (a rejectable state in the per-signature
// dispatch). Any non-zero value collision between SchemeECDSA or
// SchemeBLS and 0x00 would break that reservation.
//
// This property is distinct from TestSchemeBLS_Value and
// TestSchemeECDSA_Value (which lock exact values). A future change
// that moves SchemeECDSA from 0x01 to 0x03 would be caught by its
// value-lock test; a change that moves it to 0x00 would be caught by
// this test.
func TestSchemeValues_NonZero(t *testing.T) {
	if SchemeBLS == 0x00 {
		t.Fatal("SchemeBLS is 0x00. Wave 2 reserves 0x00 for " +
			"'scheme not declared'. Pick a non-zero value.")
	}
	if SchemeECDSA == 0x00 {
		t.Fatal("SchemeECDSA is 0x00. Wave 2 reserves 0x00 for " +
			"'scheme not declared'. Pick a non-zero value.")
	}
}
`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "synthetic.go", src, parser.ParseComments)
	if err != nil {
		panic(fmt.Sprintf("internal error: failed to parse synthetic TestSchemeValues_NonZero: %v", err))
	}
	// Return the lone FuncDecl.
	for _, decl := range parsed.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok {
			return fd
		}
	}
	panic("internal error: synthetic source did not contain FuncDecl")
}

// ══════════════════════════════════════════════════════════════════════
// Item 4: t.Logf → t.Errorf in dispatch isolation test
// ══════════════════════════════════════════════════════════════════════

func item4_LogfToErrorf(f *ast.File) MutationResult {
	result := MutationResult{Item: 4, Name: "t.Logf → t.Errorf in dispatch isolation test"}

	target := findFuncDecl(f, "TestVerifyWitnessCosignatures_ECDSAHead_DoesNotConsultBLSVerifier")
	if target == nil {
		result.Err = fmt.Errorf("TestVerifyWitnessCosignatures_ECDSAHead_DoesNotConsultBLSVerifier not found")
		return result
	}

	// Walk the body and find any `t.Logf(...)` call inside an `if err != nil {}` block.
	mutated := false
	ast.Inspect(target.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != "t" {
			return true
		}
		if sel.Sel.Name == "Logf" {
			// Change to Errorf. Also update the leading string
			// argument to reflect that this IS now a test failure.
			sel.Sel.Name = "Errorf"
			if len(call.Args) > 0 {
				if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					// Replace the leading string; the old one explicitly
					// said "not a test failure" which is now misleading.
					lit.Value = `"ECDSA verification failed inside the dispatch-isolation test. " +
	"Dispatch routing was correct (BLS verifier was not consulted), but " +
	"the ECDSA verification step itself produced an error, indicating " +
	"fixture drift in witness construction, signing, or ID derivation. " +
	"Error: %v"`
				}
			}
			mutated = true
		}
		return true
	})

	if !mutated {
		result.Skipped = true
		result.SkipNote = "no t.Logf call found (already Errorf, or test was restructured)"
		return result
	}
	result.Changed = true
	return result
}

// ══════════════════════════════════════════════════════════════════════
// Item 5: Remove pubKeyID[31] = byte(i) byte-overwrite
// ══════════════════════════════════════════════════════════════════════

func item5_RemovePubKeyIDByteOverwrite(f *ast.File) MutationResult {
	result := MutationResult{Item: 5, Name: "Remove pubKeyID[31] = byte(i) byte-overwrite"}

	target := findFuncDecl(f, "TestVerifyWitnessCosignatures_ECDSAHead_DoesNotConsultBLSVerifier")
	if target == nil {
		result.Err = fmt.Errorf("target test function not found")
		return result
	}

	removed := false
	// Walk block-by-block and filter out any assignment of the form
	// `pubKeyID[31] = byte(i)` (or any index with any RHS).
	ast.Inspect(target.Body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		newList := make([]ast.Stmt, 0, len(block.List))
		for _, stmt := range block.List {
			if isPubKeyIDByteOverwrite(stmt) {
				removed = true
				continue
			}
			newList = append(newList, stmt)
		}
		block.List = newList
		return true
	})

	if !removed {
		result.Skipped = true
		result.SkipNote = "no pubKeyID[...] = byte(...) statement found"
		return result
	}
	result.Changed = true
	return result
}

// isPubKeyIDByteOverwrite detects `pubKeyID[<anything>] = <anything>`.
func isPubKeyIDByteOverwrite(stmt ast.Stmt) bool {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || assign.Tok != token.ASSIGN {
		return false
	}
	if len(assign.Lhs) != 1 {
		return false
	}
	idx, ok := assign.Lhs[0].(*ast.IndexExpr)
	if !ok {
		return false
	}
	ident, ok := idx.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "pubKeyID"
}

// ══════════════════════════════════════════════════════════════════════
// Item 6: Update file-header docstring to describe raw-coordinate
//         construction (not cofactor multiplication)
// ══════════════════════════════════════════════════════════════════════

func item6_FixFileHeaderDocstring(fset *token.FileSet, f *ast.File) MutationResult {
	result := MutationResult{Item: 6, Name: "Fix file-header docstring (cofactor → raw coordinates)"}

	// File-level comments are in f.Comments. We find the top-of-file
	// block comment (the /* FILE PATH: ... */ one) and rewrite the
	// stale paragraph.
	//
	// Instead of trying to mutate individual comment text (which is
	// fragile via go/ast), we detect the stale phrase and replace the
	// entire file-header comment with a correct version.

	const staleMarker = "multiplying the G2 generator by the curve's cofactor"
	const correctHeader = `/*
FILE PATH:

	crypto/signatures/bls_gaps_test.go

DESCRIPTION:

	Closes four test coverage gaps identified in Wave 1 review:

	  1. TestSchemeBLS_Value / TestSchemeECDSA_Value / TestSchemeValues_NonZero
	     Byte-level locks on the scheme tag constants that drive
	     dispatch routing. Without these, a silent byte flip (e.g.,
	     SchemeBLS going from 0x02 to any other value) would cause
	     BLS-signed heads to route to the ECDSA verifier, parse-fail
	     silently, and return empty validation results. The dispatch
	     layer has no other guard against this; these tests are the
	     guard.

	  2. TestVerifyWitnessCosignatures_ECDSAHead_DoesNotConsultBLSVerifier
	     Negative-space dispatch test. Confirms that when a
	     CosignedTreeHead carries SchemeTag=SchemeECDSA, the dispatcher
	     does NOT consult the BLSVerifier implementation. Uses a
	     panicking BLSVerifier as tripwire: if the dispatcher ever
	     accidentally routes ECDSA through BLS parsing logic, the
	     test panics with a clear message. Today's code routes
	     correctly; this test guards against future regressions.

	  3. TestParseBLSPubKey_NotInSubgroup
	     Exercises the prime-order-subgroup check that gnark performs
	     inside G2Affine.SetBytes. Constructs a G2 point that is
	     on-curve but outside the prime-order subgroup, then confirms
	     ParseBLSPubKey rejects it with the correct typed error
	     (ErrBLSPubKeyNotInSubgroup).

	     CONSTRUCTION: the test solves the G2 twist curve equation
	     y^2 = x^3 + b directly (where b = 4 + 4i). We iterate small
	     x values, compute rhs = x^3 + b, take a square root, verify
	     it squared equals rhs, then construct a G2Affine with those
	     raw coordinates. The resulting point is on-curve; with
	     overwhelming probability it is NOT in the prime-order
	     subgroup (which has measure 1/cofactor of the full curve).

	     This avoids hardcoding the 512-bit BLS12-381 G2 cofactor as
	     a hex literal (which would couple the test to a specific
	     library encoding). The curve equation is universal across
	     every BLS12-381 implementation.

LOCATION DISCIPLINE:

	These tests live in a single gap-filling file rather than being
	scattered across bls_lock_test.go, bls_verifier_test.go, and
	bls_rogue_key_test.go. Rationale: they are merge-blocker tests
	added to close specific review gaps; keeping them in one file
	makes the Wave 1 patch history legible.
*/`

	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if strings.Contains(c.Text, staleMarker) {
				c.Text = correctHeader
				result.Changed = true
				return result
			}
		}
	}

	result.Skipped = true
	result.SkipNote = "file header does not contain the stale cofactor marker (already fixed)"
	return result
}

// ══════════════════════════════════════════════════════════════════════
// Item 7: Align BLSPoPDomainTag docstring with its actual value
// ══════════════════════════════════════════════════════════════════════

func item7_AlignPoPDocstring(fset *token.FileSet, f *ast.File) MutationResult {
	result := MutationResult{Item: 7, Name: "Align BLSPoPDomainTag docstring with its actual value"}

	// Find BLSPoPDomainTag's const declaration.
	//
	// Strategy: walk GenDecls, find the one containing BLSPoPDomainTag,
	// extract the actual string value, and ensure the attached Doc
	// comment names that same value.

	var targetGen *ast.GenDecl
	var targetSpec *ast.ValueSpec
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			for _, n := range vs.Names {
				if n.Name == "BLSPoPDomainTag" {
					targetGen = gen
					targetSpec = vs
					break
				}
			}
		}
	}

	if targetSpec == nil {
		result.Err = fmt.Errorf("BLSPoPDomainTag constant not found")
		return result
	}

	// Extract the actual string value.
	if len(targetSpec.Values) == 0 {
		result.Err = fmt.Errorf("BLSPoPDomainTag has no value expression")
		return result
	}
	lit, ok := targetSpec.Values[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		result.Err = fmt.Errorf("BLSPoPDomainTag value is not a string literal")
		return result
	}
	actualValue := strings.Trim(lit.Value, `"`)

	// The Doc comment may be on the GenDecl or on the ValueSpec
	// depending on grouping.
	var doc *ast.CommentGroup
	if targetSpec.Doc != nil {
		doc = targetSpec.Doc
	} else if targetGen.Doc != nil && len(targetGen.Specs) == 1 {
		doc = targetGen.Doc
	}

	if doc == nil {
		result.Skipped = true
		result.SkipNote = "BLSPoPDomainTag has no attached docstring to align"
		return result
	}

	// Look for any quoted "ORTHOLOG_BLS_..." substring in the doc
	// comment and ensure it matches the actual value.
	changed := false
	for _, c := range doc.List {
		// The stale comment may contain any case variant; we do a
		// case-insensitive search for the tag prefix, then normalize
		// to the exact value.
		origText := c.Text
		newText := replaceTagInCommentText(origText, actualValue)
		if newText != origText {
			c.Text = newText
			changed = true
		}
	}

	if !changed {
		result.Skipped = true
		result.SkipNote = fmt.Sprintf("docstring already matches value %q", actualValue)
		return result
	}
	result.Changed = true
	return result
}

// replaceTagInCommentText finds any quoted string starting with
// "ORTHOLOG_BLS_" inside commentText and replaces it with the
// authoritative value. This handles case variations like
// "ORTHOLOG_BLS_POP_V1_" vs "ORTHOLOG_BLS_PoP_V1_".
func replaceTagInCommentText(commentText, authoritative string) string {
	// Search for any occurrence of "ORTHOLOG_BLS_" (anchored inside
	// quotes) and replace the whole quoted literal with the
	// authoritative value.
	//
	// We do this via a simple scan because regex over comment text
	// is fiddly, and we'd rather handle one substitution explicitly.
	result := commentText
	for {
		idx := strings.Index(result, `"ORTHOLOG_BLS_`)
		if idx < 0 {
			break
		}
		// Find the closing quote.
		end := strings.IndexByte(result[idx+1:], '"')
		if end < 0 {
			break
		}
		end += idx + 1
		// Replace the full quoted substring (including quotes) with
		// the authoritative quoted value.
		target := `"` + authoritative + `"`
		if result[idx:end+1] == target {
			// Already matches; advance past to avoid infinite loop.
			result = result[:end+1] + result[end+1:]
			break
		}
		result = result[:idx] + target + result[end+1:]
	}
	return result
}

// ══════════════════════════════════════════════════════════════════════
// Item 8: Mutation probe reminder (not a code mutation)
// ══════════════════════════════════════════════════════════════════════

func item8_MutationProbeReminder() MutationResult {
	return MutationResult{
		Item:    8,
		Name:    "Mutation probe for TestParseBLSPubKey_NotInSubgroup",
		Skipped: true,
		SkipNote: `manual step — run this to verify the test actually guards the classification logic:

  1. In crypto/signatures/bls_signer.go, inside ParseBLSPubKey,
     temporarily comment out the "subgroup" classification branch:

         // if strings.Contains(err.Error(), "subgroup") {
         //     return nil, fmt.Errorf("%w: %v", ErrBLSPubKeyNotInSubgroup, err)
         // }
         return nil, fmt.Errorf("%w: %v", ErrBLSPubKeyNotOnCurve, err)

  2. Run: go test -run 'TestParseBLSPubKey_NotInSubgroup' ./crypto/signatures/...

  3. CONFIRM: the test MUST fail with "got: ErrBLSPubKeyNotOnCurve,
     want: ErrBLSPubKeyNotInSubgroup" — this proves the test exercises
     the classification logic.

  4. Restore the classification branch.

  5. Re-run. Test must pass again.

  If the test passes with the branch commented out, it is NOT guarding
  the classification logic — investigate before merging Wave 1.`,
	}
}
