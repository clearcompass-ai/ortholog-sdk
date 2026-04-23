// cmd/audit-v775/main.go
//
// v7.75 "Provenance" structural scope auditor.
//
// Walks the Ortholog SDK AST to produce a verifiable file-scope contract
// for the v7.75 release. Emits three artifacts:
//
//   audits/v7.75-structural-scope.md — production files in scope, per-file
//                                       justification, with evidence citations
//   audits/v7.75-test-scope.md       — test files referencing affected
//                                       symbols (v7.76 fix surface)
//   audits/v7.75-evidence.json       — machine-readable evidence table
//
// Usage from repo root:
//   go run ./cmd/audit-v775
//
// Exit codes:
//   0 — audit completed, artifacts written
//   1 — load error (module won't compile; fix build first)
//   2 — specification inconsistency (spec references a symbol that does not
//       exist in the current tree)

package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// ─────────────────────────────────────────────────────────────────────
// SPEC — v7.75 Provenance scope specification
// ─────────────────────────────────────────────────────────────────────
//
// Every file that references any symbol below is in v7.75's review
// surface. Inclusion does not mean "must change" — it means "must be
// read and triaged." Files with only unchanged-behavior references are
// explicitly annotated as such in the audit output.

// changedPackages are packages whose exported surface changes in v7.75.
// Any Go file importing these is a candidate for review. "New" packages
// have no importers yet, but will appear in scope once referenced.
var changedPackages = []packageSpec{
	{Path: "github.com/clearcompass-ai/ortholog-sdk/core/vss", Kind: "new"},
	{Path: "github.com/clearcompass-ai/ortholog-sdk/crypto/artifact", Kind: "modified"},
	{Path: "github.com/clearcompass-ai/ortholog-sdk/crypto/escrow", Kind: "modified"},
	{Path: "github.com/clearcompass-ai/ortholog-sdk/exchange/identity", Kind: "modified"},
	{Path: "github.com/clearcompass-ai/ortholog-sdk/schema", Kind: "modified"},
	{Path: "github.com/clearcompass-ai/ortholog-sdk/lifecycle", Kind: "modified"},
	{Path: "github.com/clearcompass-ai/ortholog-sdk/builder", Kind: "modified-partial"},
}

// changedSymbols are exported identifiers whose signature, shape, or
// contract changes in v7.75. Any file referencing these symbols is
// structurally in scope.
//
// The (Pkg, Name) pair uniquely identifies a symbol across the module.
// Wildcard Name="*" means "any exported symbol from this package."
var changedSymbols = []symbolSpec{
	// crypto/artifact — CFrag gains BK_i; PRE signatures add Pedersen context
	{Pkg: "crypto/artifact", Name: "CFrag", Reason: "gains BKX/BKY fields per CD3"},
	{Pkg: "crypto/artifact", Name: "KFrag", Reason: "generation takes Pedersen blinding polynomial"},
	{Pkg: "crypto/artifact", Name: "PRE_GenerateKFrags", Reason: "signature extends per CD3"},
	{Pkg: "crypto/artifact", Name: "PRE_VerifyCFrag", Reason: "adds Pedersen verification step"},
	{Pkg: "crypto/artifact", Name: "PRE_Encrypt", Reason: "re-read: composition with Pedersen binding"},
	{Pkg: "crypto/artifact", Name: "PRE_DecryptFrags", Reason: "re-read: consumes new CFrag shape"},

	// crypto/escrow — V2 becomes default for new splits
	{Pkg: "crypto/escrow", Name: "Share", Reason: "V2 fields populated by default post-v7.75"},
	{Pkg: "crypto/escrow", Name: "ValidateShareFormat", Reason: "accepts V2"},
	{Pkg: "crypto/escrow", Name: "SerializeShare", Reason: "re-read: V2 field interpretation"},
	{Pkg: "crypto/escrow", Name: "DeserializeShare", Reason: "re-read: V2 field interpretation"},
	{Pkg: "crypto/escrow", Name: "VersionV1", Reason: "legacy read-only post-v7.75"},
	{Pkg: "crypto/escrow", Name: "VersionV2", Reason: "becomes active"},

	// exchange/identity — mapping escrow switches to V2
	{Pkg: "exchange/identity", Name: "*", Reason: "mapping_escrow uses V2 + commitment entries"},

	// schema — escrow-split-commitment-v1 schema added; parameter extractor
	// recognizes new schema
	{Pkg: "schema", Name: "JSONParameterExtractor", Reason: "recognizes commitment schema"},
	{Pkg: "schema", Name: "MarshalParameters", Reason: "re-read: confirm no interaction"},

	// lifecycle — recovery fetches commitments; provision emits commitments;
	// delegation key rotation emits commitments
	{Pkg: "lifecycle", Name: "Recover", Reason: "fetches and verifies commitments"},
	{Pkg: "lifecycle", Name: "Provision", Reason: "emits commitment entry at split time"},
	{Pkg: "lifecycle", Name: "RotateDelegationKey", Reason: "emits commitment on re-split"},

	// builder — new builder for commitment entries
	{Pkg: "builder", Name: "BuildEscrowSplitCommitment", Reason: "new (v7.75)"},
}

// ─────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────

type packageSpec struct {
	Path string
	Kind string // "new" | "modified" | "modified-partial"
}

type symbolSpec struct {
	Pkg    string // short path (e.g. "crypto/escrow")
	Name   string // exported identifier or "*"
	Reason string
}

type evidence struct {
	File        string   `json:"file"`
	IsTest      bool     `json:"is_test"`
	Symbols     []string `json:"symbols"`     // symbol hits within this file
	Imports     []string `json:"imports"`     // changed packages imported
	Kind        string   `json:"kind"`        // "production" | "test"
	Disposition string   `json:"disposition"` // "in-scope" | "review-only"
	Rationale   []string `json:"rationale"`
}

// ─────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────

func main() {
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedSyntax |
			packages.NeedTypes |
			packages.NeedTypesInfo |
			packages.NeedImports |
			packages.NeedDeps,
		Tests: true, // load _test.go files
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		fatal("load failed: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		fatal("module has load errors; fix build first")
	}

	// Validate spec: every symbol referenced in changedSymbols must
	// exist in the loaded tree. A typo in the spec silently produces
	// zero hits, which would falsely report "no scope."
	if err := validateSpec(pkgs); err != nil {
		fatalWithCode(2, "spec validation failed: %v", err)
	}

	ev := map[string]*evidence{}

	changedPkgPaths := map[string]string{} // full path -> Kind
	for _, p := range changedPackages {
		changedPkgPaths[p.Path] = p.Kind
	}

	// First pass: import scan. Every file importing a changed package
	// is flagged with the imports it pulls from the changed set.
	for _, pkg := range pkgs {
		for i, file := range pkg.Syntax {
			filename := pkg.CompiledGoFiles[i]
			if !isProjectFile(filename) {
				continue
			}
			for _, imp := range file.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if _, ok := changedPkgPaths[path]; ok {
					e := ensureEvidence(ev, filename)
					e.Imports = append(e.Imports, shortPath(path))
				}
			}
		}
	}

	// Second pass: symbol reference scan. For every AST node that
	// references an identifier, check whether it resolves to a
	// changed symbol. This catches both direct calls
	// (pkg.Function(...)) and type literals (pkg.Type{...}).
	symbolIndex := buildSymbolIndex(changedSymbols)

	for _, pkg := range pkgs {
		for i, file := range pkg.Syntax {
			filename := pkg.CompiledGoFiles[i]
			if !isProjectFile(filename) {
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				obj := pkg.TypesInfo.ObjectOf(sel.Sel)
				if obj == nil || obj.Pkg() == nil {
					return true
				}
				pkgShort := shortPath(obj.Pkg().Path())
				name := obj.Name()

				if hit, reason := symbolIndex.match(pkgShort, name); hit {
					e := ensureEvidence(ev, filename)
					mark := fmt.Sprintf("%s.%s (%s)", pkgShort, name, reason)
					if !contains(e.Symbols, mark) {
						e.Symbols = append(e.Symbols, mark)
					}
				}
				return true
			})
		}
	}

	// Third pass: type literal references. Struct literals like
	// escrow.Share{...} are SelectorExpr already caught above, but
	// this pass also catches composite literals using a KeyValueExpr
	// (e.g. field name references inside a struct literal).
	// Covered by existing Inspect; kept as a comment for clarity.

	// Fourth pass: classify and emit.
	for filename, e := range ev {
		e.File = relPath(filename)
		e.IsTest = strings.HasSuffix(filename, "_test.go")
		e.Kind = "production"
		if e.IsTest {
			e.Kind = "test"
		}
		e.Disposition = classify(e)
		e.Rationale = rationale(e)
	}

	writeReports(ev)
}

// ─────────────────────────────────────────────────────────────────────
// Classification
// ─────────────────────────────────────────────────────────────────────

// classify decides whether the evidence warrants a change in v7.75 or
// is merely a review surface.
func classify(e *evidence) string {
	// Any symbol hit with a "gains" or "new" or "adds" reason is
	// definitively in scope — the symbol's contract changes.
	for _, s := range e.Symbols {
		if strings.Contains(s, "gains") ||
			strings.Contains(s, "new (v7.75)") ||
			strings.Contains(s, "signature extends") ||
			strings.Contains(s, "adds Pedersen") ||
			strings.Contains(s, "becomes active") ||
			strings.Contains(s, "accepts V2") ||
			strings.Contains(s, "V2 fields") ||
			strings.Contains(s, "emits commitment") ||
			strings.Contains(s, "verifies commitments") ||
			strings.Contains(s, "recognizes commitment") {
			return "in-scope"
		}
	}
	// Import-only hits without changed-symbol references are
	// review-only — the package import doesn't prove dependence on
	// changed behavior.
	if len(e.Imports) > 0 && len(e.Symbols) == 0 {
		return "review-only"
	}
	// Re-read symbols without signature changes are review-only
	// unless paired with a definitive hit above.
	return "review-only"
}

func rationale(e *evidence) []string {
	out := []string{}
	if len(e.Imports) > 0 {
		out = append(out, fmt.Sprintf("Imports changed packages: %s",
			strings.Join(uniq(e.Imports), ", ")))
	}
	if len(e.Symbols) > 0 {
		out = append(out, fmt.Sprintf("References changed symbols: %s",
			strings.Join(uniq(e.Symbols), "; ")))
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────
// Spec validation
// ─────────────────────────────────────────────────────────────────────

func validateSpec(pkgs []*packages.Package) error {
	byShort := map[string]*packages.Package{}
	for _, p := range pkgs {
		byShort[shortPath(p.PkgPath)] = p
	}

	var missing []string
	for _, s := range changedSymbols {
		p, ok := byShort[s.Pkg]
		if !ok {
			missing = append(missing, fmt.Sprintf("package %q not found", s.Pkg))
			continue
		}
		if s.Name == "*" {
			continue // wildcard always valid if package exists
		}
		if p.Types == nil || p.Types.Scope() == nil {
			missing = append(missing, fmt.Sprintf("package %q has no type scope", s.Pkg))
			continue
		}
		if p.Types.Scope().Lookup(s.Name) == nil {
			missing = append(missing,
				fmt.Sprintf("symbol %s.%s not found in loaded tree", s.Pkg, s.Name))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("spec references symbols that do not exist:\n  %s",
			strings.Join(missing, "\n  "))
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// Symbol index
// ─────────────────────────────────────────────────────────────────────

type symbolIndex struct {
	exact    map[string]string // "pkg.Name" -> reason
	wildcard map[string]string // "pkg" -> reason
}

func buildSymbolIndex(specs []symbolSpec) *symbolIndex {
	idx := &symbolIndex{
		exact:    map[string]string{},
		wildcard: map[string]string{},
	}
	for _, s := range specs {
		if s.Name == "*" {
			idx.wildcard[s.Pkg] = s.Reason
		} else {
			idx.exact[s.Pkg+"."+s.Name] = s.Reason
		}
	}
	return idx
}

func (i *symbolIndex) match(pkg, name string) (bool, string) {
	if reason, ok := i.exact[pkg+"."+name]; ok {
		return true, reason
	}
	if reason, ok := i.wildcard[pkg]; ok {
		return true, reason
	}
	return false, ""
}

// ─────────────────────────────────────────────────────────────────────
// Report writers
// ─────────────────────────────────────────────────────────────────────

func writeReports(ev map[string]*evidence) {
	_ = os.MkdirAll("audits", 0755)

	// Sort for deterministic output
	all := make([]*evidence, 0, len(ev))
	for _, e := range ev {
		all = append(all, e)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].File < all[j].File })

	writeProductionMD(all)
	writeTestMD(all)
	writeJSON(all)
}

func writeProductionMD(all []*evidence) {
	path := "audits/v7.75-structural-scope.md"
	f, err := os.Create(path)
	if err != nil {
		fatal("create %s: %v", path, err)
	}
	defer f.Close()

	fmt.Fprintln(f, "# v7.75 Provenance — Production File Scope")
	fmt.Fprintln(f, "")
	fmt.Fprintln(f, "Files in the production tree that reference v7.75-changed packages or symbols.")
	fmt.Fprintln(f, "Generated by `cmd/audit-v775`. Do not edit by hand.")
	fmt.Fprintln(f, "")
	fmt.Fprintln(f, "## Disposition")
	fmt.Fprintln(f, "")
	fmt.Fprintln(f, "- **in-scope** — references a symbol whose signature or contract changes; must change in v7.75.")
	fmt.Fprintln(f, "- **review-only** — imports a changed package or references a re-read symbol; must be read to confirm no dependence on changed behavior.")
	fmt.Fprintln(f, "")

	inScope, reviewOnly := 0, 0
	for _, e := range all {
		if e.IsTest {
			continue
		}
		if e.Disposition == "in-scope" {
			inScope++
		} else {
			reviewOnly++
		}
	}
	fmt.Fprintf(f, "## Summary\n\n- In-scope production files: %d\n- Review-only production files: %d\n\n", inScope, reviewOnly)

	fmt.Fprintln(f, "## Files")
	fmt.Fprintln(f, "")
	for _, e := range all {
		if e.IsTest {
			continue
		}
		fmt.Fprintf(f, "### `%s` — %s\n\n", e.File, e.Disposition)
		for _, r := range e.Rationale {
			fmt.Fprintf(f, "- %s\n", r)
		}
		fmt.Fprintln(f, "")
	}
}

func writeTestMD(all []*evidence) {
	path := "audits/v7.75-test-scope.md"
	f, err := os.Create(path)
	if err != nil {
		fatal("create %s: %v", path, err)
	}
	defer f.Close()

	fmt.Fprintln(f, "# v7.75 Provenance — Test Scope (for v7.76)")
	fmt.Fprintln(f, "")
	fmt.Fprintln(f, "Test files referencing v7.75-changed packages or symbols.")
	fmt.Fprintln(f, "These will fail under v7.75 and are scheduled for fix in v7.76.")
	fmt.Fprintln(f, "Generated by `cmd/audit-v775`. Do not edit by hand.")
	fmt.Fprintln(f, "")

	count := 0
	for _, e := range all {
		if e.IsTest {
			count++
		}
	}
	fmt.Fprintf(f, "## Summary\n\n- Test files in v7.76 fix surface: %d\n\n", count)

	fmt.Fprintln(f, "## Files")
	fmt.Fprintln(f, "")
	for _, e := range all {
		if !e.IsTest {
			continue
		}
		fmt.Fprintf(f, "### `%s`\n\n", e.File)
		for _, r := range e.Rationale {
			fmt.Fprintf(f, "- %s\n", r)
		}
		fmt.Fprintln(f, "")
	}
}

func writeJSON(all []*evidence) {
	path := "audits/v7.75-evidence.json"
	f, err := os.Create(path)
	if err != nil {
		fatal("create %s: %v", path, err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(all); err != nil {
		fatal("encode json: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────

const modulePath = "github.com/clearcompass-ai/ortholog-sdk/"

func shortPath(full string) string {
	return strings.TrimPrefix(full, modulePath)
}

func isProjectFile(filename string) bool {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return false
	}
	cwd, err := os.Getwd()
	if err != nil {
		return false
	}
	return strings.HasPrefix(abs, cwd)
}

func relPath(filename string) string {
	cwd, _ := os.Getwd()
	rel, err := filepath.Rel(cwd, filename)
	if err != nil {
		return filename
	}
	return rel
}

func ensureEvidence(m map[string]*evidence, filename string) *evidence {
	if e, ok := m[filename]; ok {
		return e
	}
	e := &evidence{}
	m[filename] = e
	return e
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "audit-v775: "+format+"\n", args...)
	os.Exit(1)
}

func fatalWithCode(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "audit-v775: "+format+"\n", args...)
	os.Exit(code)
}

var _ = token.NoPos // keep import
