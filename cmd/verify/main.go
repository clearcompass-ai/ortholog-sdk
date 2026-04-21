// Command inspect-envelope reads every file in core/envelope/ (including
// files Go might ignore) and reports what the Go parser actually sees.
//
// PURPOSE: diagnose the "found packages envelope and tests in
// /core/envelope" error by listing, per-file, the package declaration,
// imports, and top-level declarations. Any file that declares a
// package OTHER than "envelope" is the source of the error.
//
// Unlike `go list`, this tool inspects EVERY .go file regardless of
// build tags, file suffixes, or go.mod exclusions — so it can spot
// a stray `package tests` file that Go would otherwise skip.
//
// USAGE:
//
//	cd ~/workspace/ortholog-sdk
//	go run /path/to/inspect_envelope.go
//
// OUTPUT: one section per file, plus a summary at the end listing
// any files that disagree with the directory-wide package name.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const envelopeDir = "core/envelope"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if _, err := os.Stat("go.mod"); err != nil {
		return fmt.Errorf("go.mod not found — run from repo root")
	}
	if _, err := os.Stat(envelopeDir); err != nil {
		return fmt.Errorf("%s not found", envelopeDir)
	}

	// Raw directory listing (equivalent of ls -la but programmatic).
	// This is what the filesystem has, regardless of what Go parses.
	entries, err := os.ReadDir(envelopeDir)
	if err != nil {
		return err
	}

	fmt.Printf("=== Raw directory listing: %s ===\n", envelopeDir)
	for _, e := range entries {
		info, _ := e.Info()
		typ := "file"
		if e.IsDir() {
			typ = "dir"
		}
		fmt.Printf("  %-40s %s  %d bytes\n", e.Name(), typ, info.Size())
	}
	fmt.Println()

	// Now parse every .go file (any suffix, not just _test.go).
	// Also parse files that match *.go.* patterns (like .bak-ast).
	// We report whether they parse cleanly and what package they declare.
	type fileReport struct {
		name     string
		parsed   bool
		pkg      string
		imports  []string
		topLevel []string // function/type/var/const names
		parseErr string
	}

	var reports []fileReport
	fset := token.NewFileSet()

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		path := filepath.Join(envelopeDir, name)

		// Parse anything that LOOKS like Go source. This catches
		// .go files AND .go.bak* files which Go's tooling ignores
		// but which might have been mistakenly named or placed.
		if !strings.Contains(name, ".go") {
			continue
		}

		report := fileReport{name: name}

		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			report.parseErr = err.Error()
			reports = append(reports, report)
			continue
		}

		report.parsed = true
		report.pkg = file.Name.Name

		for _, imp := range file.Imports {
			report.imports = append(report.imports, imp.Path.Value)
		}

		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				recv := ""
				if d.Recv != nil && len(d.Recv.List) > 0 {
					recv = "(method) "
				}
				report.topLevel = append(report.topLevel, recv+"func "+d.Name.Name)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						report.topLevel = append(report.topLevel, "type "+s.Name.Name)
					case *ast.ValueSpec:
						for _, n := range s.Names {
							kind := "var"
							if d.Tok == token.CONST {
								kind = "const"
							}
							report.topLevel = append(report.topLevel, kind+" "+n.Name)
						}
					}
				}
			}
		}

		reports = append(reports, report)
	}

	// Per-file detail.
	sort.Slice(reports, func(i, j int) bool { return reports[i].name < reports[j].name })

	fmt.Println("=== Per-file AST inspection ===")
	for _, r := range reports {
		fmt.Printf("\n--- %s ---\n", r.name)
		if !r.parsed {
			fmt.Printf("  PARSE ERROR: %s\n", r.parseErr)
			continue
		}
		fmt.Printf("  package: %s\n", r.pkg)
		if len(r.imports) > 0 {
			fmt.Printf("  imports: %d\n", len(r.imports))
			for _, imp := range r.imports {
				fmt.Printf("    %s\n", imp)
			}
		}
		if len(r.topLevel) > 0 {
			fmt.Printf("  top-level decls: %d\n", len(r.topLevel))
			if len(r.topLevel) <= 8 {
				for _, decl := range r.topLevel {
					fmt.Printf("    %s\n", decl)
				}
			} else {
				for _, decl := range r.topLevel[:5] {
					fmt.Printf("    %s\n", decl)
				}
				fmt.Printf("    ... and %d more\n", len(r.topLevel)-5)
			}
		}
	}

	// Summary: find any file disagreeing with the dominant package.
	fmt.Println("\n=== Summary ===")
	pkgCount := map[string]int{}
	for _, r := range reports {
		if r.parsed {
			pkgCount[r.pkg]++
		}
	}
	fmt.Printf("Package distribution across %s:\n", envelopeDir)
	for pkg, count := range pkgCount {
		fmt.Printf("  %s: %d files\n", pkg, count)
	}

	// Identify outliers.
	var dominant string
	var dominantCount int
	for pkg, count := range pkgCount {
		if count > dominantCount {
			dominant = pkg
			dominantCount = count
		}
	}
	fmt.Printf("\nDominant package: %s\n", dominant)
	outliers := []fileReport{}
	for _, r := range reports {
		if r.parsed && r.pkg != dominant {
			outliers = append(outliers, r)
		}
	}
	if len(outliers) == 0 {
		fmt.Println("No outliers — every parsed file declares 'package " + dominant + "'.")
	} else {
		fmt.Printf("\n⚠️  %d OUTLIER FILE(S):\n", len(outliers))
		for _, o := range outliers {
			fmt.Printf("  %s declares 'package %s' — expected 'package %s'\n",
				o.name, o.pkg, dominant)
		}
	}

	// Files Go would COMPILE (the _test.go split matters).
	fmt.Println("\n=== Go compilation view ===")
	prod := []string{}
	tests := []string{}
	ignored := []string{}
	for _, r := range reports {
		if !r.parsed {
			ignored = append(ignored, r.name+"  (parse error)")
			continue
		}
		switch {
		case strings.HasSuffix(r.name, "_test.go"):
			tests = append(tests, r.name+"  (package "+r.pkg+")")
		case strings.HasSuffix(r.name, ".go"):
			prod = append(prod, r.name+"  (package "+r.pkg+")")
		default:
			ignored = append(ignored, r.name+"  (not .go)")
		}
	}
	fmt.Printf("Production files (compiled by `go build`): %d\n", len(prod))
	for _, f := range prod {
		fmt.Printf("  %s\n", f)
	}
	fmt.Printf("Test files (compiled by `go test`): %d\n", len(tests))
	for _, f := range tests {
		fmt.Printf("  %s\n", f)
	}
	fmt.Printf("Ignored by Go tooling: %d\n", len(ignored))
	for _, f := range ignored {
		fmt.Printf("  %s\n", f)
	}

	return nil
}
