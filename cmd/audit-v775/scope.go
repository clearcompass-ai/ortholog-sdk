// cmd/audit-v775/scope.go — v7.75 Provenance structural scope audit.
//
// Walks the Ortholog SDK AST to produce a verifiable file-scope
// contract for the v7.75 release. Emits three artifacts:
//
//   audits/v7.75-structural-scope.md — production files in scope
//   audits/v7.75-test-scope.md       — test files referencing scope
//   audits/v7.75-evidence.json       — machine-readable evidence
//
// Exit codes:
//   0 — audit completed, artifacts written
//   1 — load error (module won't compile; fix build first)
//   2 — specification inconsistency (spec references a missing symbol)

package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Report writers (writeReports, writeProductionMD, writeTestMD,
// writeJSON) live in scope_reports.go to keep this file under the
// 300-line budget.

// Scope specification (changedPackages, changedSymbols), data
// types (packageSpec, symbolSpec, evidence), and the symbolIndex
// helpers live in scope_spec.go.

func runScope() {
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedSyntax |
			packages.NeedTypes |
			packages.NeedTypesInfo |
			packages.NeedImports |
			packages.NeedDeps,
		Tests: true,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		fatal("load failed: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		fatal("module has load errors; fix build first")
	}
	if err := validateSpec(pkgs); err != nil {
		fatalWithCode(2, "spec validation failed: %v", err)
	}

	ev := map[string]*evidence{}
	changedPkgPaths := map[string]string{}
	for _, p := range changedPackages {
		changedPkgPaths[p.Path] = p.Kind
	}

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

	symIdx := buildSymbolIndex(changedSymbols)
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
				if hit, reason := symIdx.match(pkgShort, name); hit {
					e := ensureEvidence(ev, filename)
					mark := fmt.Sprintf("%s.%s (%s)", pkgShort, name, reason)
					if !stringSliceContains(e.Symbols, mark) {
						e.Symbols = append(e.Symbols, mark)
					}
				}
				return true
			})
		}
	}

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

func classify(e *evidence) string {
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
	if len(e.Imports) > 0 && len(e.Symbols) == 0 {
		return "review-only"
	}
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

const modulePath = "github.com/clearcompass-ai/ortholog-sdk/"

func shortPath(full string) string { return strings.TrimPrefix(full, modulePath) }

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

func stringSliceContains(xs []string, s string) bool {
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

var _ = token.NoPos
