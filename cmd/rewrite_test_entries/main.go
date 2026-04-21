// Command rewrite-test-entries performs an AST-based migration of three
// legacy test-entry constructors (makeEntry, p5makeEntry, p6bSchemaEntry)
// to a single canonical constructor (buildTestEntry).
//
// DESIGN PRINCIPLES:
//   - Fail-closed: any unexpected call-site structure halts the run
//     BEFORE any files are modified. Zero partial writes.
//   - AST-only: every rewrite traverses go/ast, never regex. Multi-line
//     calls, nested calls, and tuple destructuring are handled natively.
//   - Explicit: no deprecated aliases, no legacy shims. The three old
//     helpers are DELETED; buildTestEntry is the sole survivor.
//   - Backup-first: every file modified gets a .bak-ast sibling before
//     any write. Roll back by moving .bak-ast back.
//   - Verifiable: after rewriting, the tool runs `go build ./...` and
//     rolls back if compilation fails.
//
// USAGE:
//
//	cd ~/workspace/ortholog-sdk
//	go run /path/to/rewrite_test_entries.go
//
// OR to inspect without modifying:
//
//	go run /path/to/rewrite_test_entries.go -dry-run
//
// The -dry-run flag executes phases 0-3 (discovery + validation +
// plan generation) and reports what WOULD be done, without writing.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

const (
	testsDir        = "tests"
	helpersTestFile = "tests/helpers_test.go"

	// Target functions to rewrite.
	fnMakeEntry      = "makeEntry"
	fnP5MakeEntry    = "p5makeEntry"
	fnP6bSchemaEntry = "p6bSchemaEntry"
	fnBuildTestEntry = "buildTestEntry"
)

// buildTestEntrySource is the canonical helper body that MUST exist in
// helpers_test.go after this migration. If the function is missing
// from the file, the tool will insert it.
const buildTestEntrySource = `// buildTestEntry constructs a fully-valid v6 entry for test purposes.
// This is the CANONICAL test-side entry constructor. Every test that
// builds an entry for later Store/Serialize/EntryIdentity use MUST
// go through this helper, not envelope.NewUnsignedEntry directly.
//
// Why: under v6, entries MUST carry at least one signature, and
// Signatures[0].SignerDID must equal Header.SignerDID. Raw
// NewUnsignedEntry produces an entry that cannot be safely passed to
// Serialize or MockFetcher.Store. buildTestEntry attaches a
// deterministic 64-byte zero-ECDSA signature so tests that don't care
// about signature cryptography get a valid entry without re-implementing
// the invariant dance.
//
// Tests that DO care about signature cryptography replace
// entry.Signatures after construction and re-validate.
//
// The Validate() call at the end is a safety check: if the invariant
// ever changes, the failure surfaces HERE at construction time with
// a clear message, not deep inside envelope.Serialize's panic.
func buildTestEntry(t *testing.T, h envelope.ControlHeader, payload []byte) *envelope.Entry {
	t.Helper()
	entry, err := envelope.NewUnsignedEntry(h, payload)
	if err != nil {
		t.Fatalf("buildTestEntry: NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: h.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("buildTestEntry: Validate failed — helper needs update: %v", err)
	}
	return entry
}`

// -----------------------------------------------------------------------------
// Candidate and plan types
// -----------------------------------------------------------------------------

// parentKind describes where a target call expression lives in the AST,
// determining the rewrite strategy.
type parentKind int

const (
	parentUnknown parentKind = iota

	// parentAssignSingle is `entry := fn(...)` — 1 LHS, := operator.
	parentAssignSingle

	// parentAssignTuple is `entry, canonical := fn(...)` — 2 LHS, RHS[1]
	// used (not blank).
	parentAssignTuple

	// parentAssignTupleBlank is `entry, _ := fn(...)` — 2 LHS, RHS[1]
	// is the blank identifier.
	parentAssignTupleBlank

	// parentEmbedded is the call nested inside another expression
	// (e.g., h.storeEntry(t, pos, p5makeEntry(...))). Must be rewritten
	// in-place; no tuple expansion possible.
	parentEmbedded
)

func (p parentKind) String() string {
	switch p {
	case parentAssignSingle:
		return "entry := fn(...)"
	case parentAssignTuple:
		return "entry, canonical := fn(...)"
	case parentAssignTupleBlank:
		return "entry, _ := fn(...)"
	case parentEmbedded:
		return "embedded: outer(fn(...))"
	default:
		return "unknown"
	}
}

// candidate is one call-site of a target function, with enough AST
// context to validate and rewrite.
type candidate struct {
	filePath  string          // absolute path to the source file
	file      *ast.File       // parsed file (shared across candidates in the file)
	fset      *token.FileSet  // position info
	callExpr  *ast.CallExpr   // the fn(...) call itself
	fnName    string          // makeEntry / p5makeEntry / p6bSchemaEntry
	parent    parentKind      // how this call is consumed
	assign    *ast.AssignStmt // non-nil when parent is an assignment
	block     *ast.BlockStmt  // enclosing block (for statement insertion)
	stmtIdx   int             // index in block.List of the enclosing statement
	canonName string          // for parentAssignTuple: the LHS[1] ident name
}

// pos returns a human-readable file:line for reporting.
func (c *candidate) pos() string {
	p := c.fset.Position(c.callExpr.Pos())
	return fmt.Sprintf("%s:%d", p.Filename, p.Line)
}

// validationFailure records a call site that doesn't match expected structure.
type validationFailure struct {
	position string
	fnName   string
	reason   string
}

func (v validationFailure) String() string {
	return fmt.Sprintf("%s %s(...): %s", v.position, v.fnName, v.reason)
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

func main() {
	dryRun := flag.Bool("dry-run", false,
		"Run phases 0-3 (discover, validate, plan) without modifying files")
	flag.Parse()

	if err := run(*dryRun); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run(dryRun bool) error {
	// Verify we're in repo root.
	if _, err := os.Stat("go.mod"); err != nil {
		return fmt.Errorf("go.mod not found — run from repo root")
	}

	fset := token.NewFileSet()

	// --------------------------------------------------------------
	// Phase 0 — Parse all test files
	// --------------------------------------------------------------
	fmt.Println("Phase 0: parsing test files...")
	files, err := parseTestFiles(fset)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	fmt.Printf("  parsed %d files\n", len(files))

	// --------------------------------------------------------------
	// Phase 1 — Discovery
	// --------------------------------------------------------------
	fmt.Println("\nPhase 1: discovering call sites...")
	var candidates []*candidate
	for path, file := range files {
		found := discoverCandidates(fset, file, path)
		candidates = append(candidates, found...)
	}

	byFn := map[string]int{}
	for _, c := range candidates {
		byFn[c.fnName]++
	}
	fmt.Printf("  total candidates: %d\n", len(candidates))
	for _, name := range []string{fnMakeEntry, fnP5MakeEntry, fnP6bSchemaEntry} {
		fmt.Printf("    %-20s %d\n", name, byFn[name])
	}

	// --------------------------------------------------------------
	// Phase 2 — Validation (fail-closed)
	// --------------------------------------------------------------
	fmt.Println("\nPhase 2: validating call sites...")
	failures := validateCandidates(candidates)
	if len(failures) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d validation failure(s):\n", len(failures))
		for _, f := range failures {
			fmt.Fprintf(os.Stderr, "  %s\n", f)
		}
		return fmt.Errorf("validation failed — no files modified")
	}
	fmt.Printf("  all %d call sites passed validation\n", len(candidates))

	// Count parent kinds for reporting.
	byKind := map[parentKind]int{}
	for _, c := range candidates {
		byKind[c.parent]++
	}
	fmt.Println("\n  parent-kind breakdown:")
	for _, k := range []parentKind{parentAssignSingle, parentAssignTuple, parentAssignTupleBlank, parentEmbedded} {
		fmt.Printf("    %-40s %d\n", k, byKind[k])
	}

	// --------------------------------------------------------------
	// Phase 3 — Rewrite plan (print, halt if dry-run)
	// --------------------------------------------------------------
	if dryRun {
		fmt.Println("\nDry run complete. No files modified.")
		fmt.Println("Sample rewrites (first 5):")
		for i, c := range candidates {
			if i >= 5 {
				break
			}
			fmt.Printf("  %s: %s → buildTestEntry\n", c.pos(), c.fnName)
		}
		return nil
	}

	// --------------------------------------------------------------
	// Phase 4 — Apply rewrites
	// --------------------------------------------------------------
	fmt.Println("\nPhase 4: applying rewrites...")
	modifiedFiles, err := applyRewrites(fset, files, candidates)
	if err != nil {
		return fmt.Errorf("rewrite: %w", err)
	}
	fmt.Printf("  rewrote %d call sites across %d files\n",
		len(candidates), len(modifiedFiles))

	// --------------------------------------------------------------
	// Phase 5 — Ensure buildTestEntry exists, delete legacy helpers
	// --------------------------------------------------------------
	fmt.Println("\nPhase 5: updating helper definitions...")
	if err := ensureBuildTestEntry(fset, files); err != nil {
		return fmt.Errorf("ensure buildTestEntry: %w", err)
	}
	if err := deleteLegacyHelpers(fset, files); err != nil {
		return fmt.Errorf("delete legacy: %w", err)
	}

	// --------------------------------------------------------------
	// Phase 6 — Write files with backups
	// --------------------------------------------------------------
	fmt.Println("\nPhase 6: writing files (with .bak-ast backups)...")
	written, err := writeFiles(fset, files, modifiedFiles)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	fmt.Printf("  wrote %d files\n", written)

	// --------------------------------------------------------------
	// Phase 7 — Compile verification
	// --------------------------------------------------------------
	fmt.Println("\nPhase 7: verifying compile with `go build ./...`...")
	if err := runGoBuild(); err != nil {
		fmt.Fprintf(os.Stderr, "\ncompile FAILED:\n%v\n", err)
		fmt.Fprintln(os.Stderr, "rolling back from .bak-ast files...")
		rollback(modifiedFiles)
		return fmt.Errorf("compile verification failed — rolled back")
	}
	fmt.Println("  compile clean")

	fmt.Println("\nMigration complete. Review diff with:")
	fmt.Println("  git diff tests/")
	fmt.Println("Cleanup backups after review:")
	fmt.Println("  rm tests/*.bak-ast")
	return nil
}

// -----------------------------------------------------------------------------
// Phase 0 — Parse
// -----------------------------------------------------------------------------

func parseTestFiles(fset *token.FileSet) (map[string]*ast.File, error) {
	files := map[string]*ast.File{}
	entries, err := os.ReadDir(testsDir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Only parse *_test.go, and skip .bak* files.
		if !strings.HasSuffix(name, "_test.go") {
			continue
		}
		if strings.Contains(name, ".bak") {
			continue
		}
		path := filepath.Join(testsDir, name)
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		files[path] = file
	}
	return files, nil
}

// -----------------------------------------------------------------------------
// Phase 1 — Discovery
// -----------------------------------------------------------------------------

func discoverCandidates(fset *token.FileSet, file *ast.File, path string) []*candidate {
	var out []*candidate

	// We walk statements in function bodies and remember the enclosing
	// BlockStmt + index so rewrites can splice statements.
	ast.Inspect(file, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i, stmt := range block.List {
			cands := scanStatementForTargets(fset, file, path, stmt, block, i)
			out = append(out, cands...)
		}
		return true
	})
	return out
}

// scanStatementForTargets finds all target calls in a single statement and
// classifies each by its parent kind. A single statement CAN contain
// multiple target calls if they are nested as args in a larger expression.
func scanStatementForTargets(
	fset *token.FileSet, file *ast.File, path string,
	stmt ast.Stmt, block *ast.BlockStmt, stmtIdx int,
) []*candidate {
	var out []*candidate

	// First, check if the statement itself IS the target call or contains
	// it at the top level (i.e., the parent is the assignment or expr stmt
	// directly).
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		if len(s.Rhs) == 1 {
			if call := asTargetCall(s.Rhs[0]); call != nil {
				c := &candidate{
					filePath: path, file: file, fset: fset,
					callExpr: call, fnName: callFnName(call),
					assign: s, block: block, stmtIdx: stmtIdx,
				}
				// Classify assignment parent.
				switch len(s.Lhs) {
				case 1:
					c.parent = parentAssignSingle
				case 2:
					if isBlankIdent(s.Lhs[1]) {
						c.parent = parentAssignTupleBlank
					} else {
						c.parent = parentAssignTuple
						if id, ok := s.Lhs[1].(*ast.Ident); ok {
							c.canonName = id.Name
						}
					}
				default:
					c.parent = parentUnknown
				}
				out = append(out, c)
				return out
			}
		}
	}

	// Also search for EMBEDDED target calls (nested as args in other exprs).
	// These are rewritten in-place; we don't need the parent statement
	// for tuple expansion.
	ast.Inspect(stmt, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if callFnName(call) == "" {
			return true
		}
		// Skip if this is the top-level call we already captured above.
		if already(out, call) {
			return true
		}
		// Embedded call — rewrite in place, no tuple expansion.
		c := &candidate{
			filePath: path, file: file, fset: fset,
			callExpr: call, fnName: callFnName(call),
			parent: parentEmbedded,
			block:  block, stmtIdx: stmtIdx,
		}
		out = append(out, c)
		return true
	})
	return out
}

func already(cands []*candidate, call *ast.CallExpr) bool {
	for _, c := range cands {
		if c.callExpr == call {
			return true
		}
	}
	return false
}

// asTargetCall returns the CallExpr if expr is a target function call,
// else nil.
func asTargetCall(expr ast.Expr) *ast.CallExpr {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil
	}
	if callFnName(call) == "" {
		return nil
	}
	return call
}

// callFnName returns the identifier name if the call's function is one of
// our targets; empty string otherwise. Only matches unqualified idents
// (not SelectorExpr like pkg.Fn).
func callFnName(call *ast.CallExpr) string {
	id, ok := call.Fun.(*ast.Ident)
	if !ok {
		return ""
	}
	switch id.Name {
	case fnMakeEntry, fnP5MakeEntry, fnP6bSchemaEntry:
		return id.Name
	}
	return ""
}

func isBlankIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "_"
}

// -----------------------------------------------------------------------------
// Phase 2 — Validation
// -----------------------------------------------------------------------------

func validateCandidates(candidates []*candidate) []validationFailure {
	var failures []validationFailure
	for _, c := range candidates {
		if f := validateOne(c); f != nil {
			failures = append(failures, *f)
		}
	}
	// Sort failures by file:line for readable reports.
	sort.Slice(failures, func(i, j int) bool {
		return failures[i].position < failures[j].position
	})
	return failures
}

func validateOne(c *candidate) *validationFailure {
	fail := func(reason string) *validationFailure {
		return &validationFailure{position: c.pos(), fnName: c.fnName, reason: reason}
	}

	// Expected arg count per function.
	wantArgs := 3
	if c.fnName == fnP6bSchemaEntry {
		wantArgs = 2 // (t, payload) — destination and DID are baked into the helper
	}
	if len(c.callExpr.Args) != wantArgs {
		return fail(fmt.Sprintf("expected %d args, got %d", wantArgs, len(c.callExpr.Args)))
	}

	// Arg 0 must be identifier `t`.
	if id, ok := c.callExpr.Args[0].(*ast.Ident); !ok || id.Name != "t" {
		return fail("first arg must be identifier 't'")
	}

	// Parent kind must be recognized.
	if c.parent == parentUnknown {
		return fail("unrecognized call-site structure; expected assignment or embedded form")
	}

	// Only makeEntry supports parentAssignTuple (since it's the only
	// tuple-returning function). p5makeEntry and p6bSchemaEntry return
	// single value.
	if c.fnName != fnMakeEntry && (c.parent == parentAssignTuple || c.parent == parentAssignTupleBlank) {
		return fail(fmt.Sprintf("%s returns single value but parent is tuple form",
			c.fnName))
	}

	// makeEntry returning single value is unusual — flag for review.
	if c.fnName == fnMakeEntry && c.parent == parentAssignSingle {
		return fail("makeEntry returns (entry, canonical) but LHS has 1 variable; ambiguous")
	}

	return nil
}

// -----------------------------------------------------------------------------
// Phase 4 — Apply rewrites
// -----------------------------------------------------------------------------

// applyRewrites modifies AST nodes in-place. Returns the set of file paths
// that were modified. Caller is responsible for writing them out.
func applyRewrites(fset *token.FileSet, files map[string]*ast.File, candidates []*candidate) (map[string]bool, error) {
	modified := map[string]bool{}

	// We need to process tuple-expansion candidates in reverse stmt-index
	// order within each block, so earlier insertions don't shift later
	// indexes. Group by block and sort.
	byBlock := map[*ast.BlockStmt][]*candidate{}
	inPlace := []*candidate{}
	for _, c := range candidates {
		switch c.parent {
		case parentAssignTuple, parentAssignTupleBlank, parentAssignSingle:
			byBlock[c.block] = append(byBlock[c.block], c)
		case parentEmbedded:
			inPlace = append(inPlace, c)
		}
	}

	// Handle in-place rewrites first (embedded calls). Just rename the ident.
	for _, c := range inPlace {
		renameCallIdent(c.callExpr, fnBuildTestEntry)
		// Adjust arg count for p6bSchemaEntry → buildTestEntry (see below).
		if c.fnName == fnP6bSchemaEntry {
			if err := rewriteP6bArgs(c); err != nil {
				return nil, fmt.Errorf("%s: %w", c.pos(), err)
			}
		}
		modified[c.filePath] = true
	}

	// Handle assignment rewrites per block, in reverse stmt order.
	for block, cands := range byBlock {
		sort.Slice(cands, func(i, j int) bool {
			return cands[i].stmtIdx > cands[j].stmtIdx
		})
		for _, c := range cands {
			if err := rewriteAssignment(block, c); err != nil {
				return nil, fmt.Errorf("%s: %w", c.pos(), err)
			}
			modified[c.filePath] = true
		}
	}
	return modified, nil
}

// renameCallIdent changes the CallExpr's function identifier.
func renameCallIdent(call *ast.CallExpr, newName string) {
	if id, ok := call.Fun.(*ast.Ident); ok {
		id.Name = newName
	}
}

// rewriteP6bArgs expands p6bSchemaEntry's 2-arg form to buildTestEntry's
// 3-arg form by inlining the baked-in header.
//
// Before: p6bSchemaEntry(t, payload)
//
//	After:  buildTestEntry(t, envelope.ControlHeader{
//	            Destination:   testDestinationDID,
//	            SignerDID:     "did:example:schema-author",
//	            AuthorityPath: sameSigner(),
//	        }, payload)
func rewriteP6bArgs(c *candidate) error {
	if len(c.callExpr.Args) != 2 {
		return fmt.Errorf("p6bSchemaEntry expected 2 args, got %d", len(c.callExpr.Args))
	}
	payload := c.callExpr.Args[1]
	header := buildP6bHeader()
	c.callExpr.Args = []ast.Expr{c.callExpr.Args[0], header, payload}
	return nil
}

// buildP6bHeader constructs the envelope.ControlHeader literal that was
// previously baked into p6bSchemaEntry.
func buildP6bHeader() ast.Expr {
	return &ast.CompositeLit{
		Type: &ast.SelectorExpr{
			X:   ast.NewIdent("envelope"),
			Sel: ast.NewIdent("ControlHeader"),
		},
		Elts: []ast.Expr{
			&ast.KeyValueExpr{
				Key:   ast.NewIdent("Destination"),
				Value: ast.NewIdent("testDestinationDID"),
			},
			&ast.KeyValueExpr{
				Key: ast.NewIdent("SignerDID"),
				Value: &ast.BasicLit{
					Kind:  token.STRING,
					Value: `"did:example:schema-author"`,
				},
			},
			&ast.KeyValueExpr{
				Key: ast.NewIdent("AuthorityPath"),
				Value: &ast.CallExpr{
					Fun: ast.NewIdent("sameSigner"),
				},
			},
		},
	}
}

// rewriteAssignment rewrites an assignment-parent candidate.
func rewriteAssignment(block *ast.BlockStmt, c *candidate) error {
	renameCallIdent(c.callExpr, fnBuildTestEntry)

	// Arg-count adjustment for p6bSchemaEntry in assignment form (rare
	// but possible).
	if c.fnName == fnP6bSchemaEntry {
		if err := rewriteP6bArgs(c); err != nil {
			return err
		}
	}

	switch c.parent {
	case parentAssignSingle:
		// entry := p5makeEntry(...) → entry := buildTestEntry(...)
		// Just the rename already applied above; nothing else to do.
		return nil

	case parentAssignTupleBlank:
		// entry, _ := makeEntry(t, h, payload)
		//   → entry := buildTestEntry(t, h, payload)
		// Reduce LHS to 1 element.
		c.assign.Lhs = c.assign.Lhs[:1]
		return nil

	case parentAssignTuple:
		// entry, canonical := makeEntry(t, h, payload)
		//   → entry := buildTestEntry(t, h, payload)
		//     canonical := envelope.Serialize(entry)
		entryIdent, ok := c.assign.Lhs[0].(*ast.Ident)
		if !ok {
			return fmt.Errorf("tuple-form LHS[0] is not an identifier")
		}
		// Mutate the existing statement to be single-LHS.
		c.assign.Lhs = c.assign.Lhs[:1]

		// Build the new statement: canonical := envelope.Serialize(entry)
		canonStmt := &ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent(c.canonName)},
			Tok: token.DEFINE,
			Rhs: []ast.Expr{
				&ast.CallExpr{
					Fun: &ast.SelectorExpr{
						X:   ast.NewIdent("envelope"),
						Sel: ast.NewIdent("Serialize"),
					},
					Args: []ast.Expr{ast.NewIdent(entryIdent.Name)},
				},
			},
		}

		// Splice it into the block after c.stmtIdx.
		// This is safe because we're processing in REVERSE stmtIdx order.
		before := block.List[:c.stmtIdx+1]
		after := block.List[c.stmtIdx+1:]
		newList := make([]ast.Stmt, 0, len(block.List)+1)
		newList = append(newList, before...)
		newList = append(newList, canonStmt)
		newList = append(newList, after...)
		block.List = newList
		return nil

	default:
		return fmt.Errorf("unexpected parent kind %v", c.parent)
	}
}

// -----------------------------------------------------------------------------
// Phase 5 — buildTestEntry exists, legacy helpers deleted
// -----------------------------------------------------------------------------

func ensureBuildTestEntry(fset *token.FileSet, files map[string]*ast.File) error {
	// helpers_test.go must exist.
	helpersFile, ok := files[helpersTestFile]
	if !ok {
		return fmt.Errorf("%s not found in parsed files", helpersTestFile)
	}

	// Does it already have buildTestEntry?
	for _, decl := range helpersFile.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name.Name == fnBuildTestEntry {
			return nil // already present, assume correct
		}
	}

	// Parse the source for buildTestEntry, lift the FuncDecl out.
	wrap := "package tests\n" + buildTestEntrySource
	tmpfset := token.NewFileSet()
	tmpfile, err := parser.ParseFile(tmpfset, "buildTestEntry.go", wrap, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("parse buildTestEntry source: %w", err)
	}
	var fn *ast.FuncDecl
	for _, d := range tmpfile.Decls {
		if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == fnBuildTestEntry {
			fn = f
			break
		}
	}
	if fn == nil {
		return fmt.Errorf("failed to lift buildTestEntry from source template")
	}
	// Append to the real helpers file.
	helpersFile.Decls = append(helpersFile.Decls, fn)
	return nil
}

func deleteLegacyHelpers(fset *token.FileSet, files map[string]*ast.File) error {
	toDelete := map[string]bool{
		fnMakeEntry:      true,
		fnP5MakeEntry:    true,
		fnP6bSchemaEntry: true,
	}
	for _, file := range files {
		filtered := file.Decls[:0]
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				filtered = append(filtered, decl)
				continue
			}
			if toDelete[fn.Name.Name] {
				continue // skip = delete
			}
			filtered = append(filtered, decl)
		}
		file.Decls = filtered
	}
	return nil
}

// -----------------------------------------------------------------------------
// Phase 6 — Write with backups
// -----------------------------------------------------------------------------

func writeFiles(fset *token.FileSet, files map[string]*ast.File, modified map[string]bool) (int, error) {
	// Always rewrite helpers_test.go even if no call-site rewrites
	// landed there, because we deleted makeEntry from it.
	modified[helpersTestFile] = true

	count := 0
	for path := range modified {
		file, ok := files[path]
		if !ok {
			continue
		}

		// Backup.
		original, err := os.ReadFile(path)
		if err != nil {
			return count, fmt.Errorf("read %s for backup: %w", path, err)
		}
		if err := os.WriteFile(path+".bak-ast", original, 0644); err != nil {
			return count, fmt.Errorf("backup %s: %w", path, err)
		}

		// Format through go/format.
		var buf strings.Builder
		if err := format.Node(&buf, fset, file); err != nil {
			return count, fmt.Errorf("format %s: %w", path, err)
		}

		if err := os.WriteFile(path, []byte(buf.String()), 0644); err != nil {
			return count, fmt.Errorf("write %s: %w", path, err)
		}
		count++
	}
	return count, nil
}

// -----------------------------------------------------------------------------
// Phase 7 — Compile verification + rollback
// -----------------------------------------------------------------------------

func runGoBuild() error {
	cmd := exec.Command("go", "build", "./...")
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w\noutput:\n%s", err, out.String())
	}
	return nil
}

func rollback(modified map[string]bool) {
	for path := range modified {
		bak := path + ".bak-ast"
		data, err := os.ReadFile(bak)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [rollback] cannot read %s: %v\n", bak, err)
			continue
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "  [rollback] cannot write %s: %v\n", path, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "  [rollback] restored %s\n", path)
	}
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

// suppress unused-import hassles if io is referenced only in this section.
var _ = io.Discard
