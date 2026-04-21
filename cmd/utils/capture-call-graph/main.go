// Command capture-call-graph produces a type-resolved call graph for
// a Go package and its usage across the SDK.
//
// DESIGN:
//   - Uses go/packages with NeedTypes + NeedTypesInfo to get exact
//     type-checker resolution for every function call. No string
//     matching, no ambiguity between methods with the same name.
//   - For the target package, finds every exported function/method
//     and records every callsite across the loaded program.
//   - Produces three outputs:
//     a. "signature.md"  — the package's exported API (signatures,
//     docs, complexity, LOC per function)
//     b. "callgraph.md"  — for each exported function, every
//     callsite across the SDK (file:line:caller)
//     c. "callgraph.json" — same data, machine-readable
//
// USAGE:
//
//	cd ~/workspace/ortholog-sdk
//	go run cmd/utils/capture-call-graph/main.go -pkg crypto
//
// Flags:
//
//	-pkg     package path relative to repo root (required)
//	         e.g. "crypto", "core/envelope", "lifecycle"
//	-outdir  output directory (default: coverage/report/graphs/<pkg>)
//
// Dependencies (add to go.mod if missing):
//
//	golang.org/x/tools/go/packages
//
// If go.mod doesn't already require it, run:
//
//	go get golang.org/x/tools/go/packages@latest
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// ---------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------

type report struct {
	Module         string           `json:"module"`
	TargetPkg      string           `json:"target_package"` // e.g. "github.com/.../crypto"
	TargetRel      string           `json:"target_rel"`     // e.g. "crypto"
	Functions      []functionRecord `json:"functions"`
	PackagesLoaded int              `json:"packages_loaded"`
	Stats          stats            `json:"stats"`
}

type functionRecord struct {
	Name           string     `json:"name"`
	Signature      string     `json:"signature"`
	IsMethod       bool       `json:"is_method"`
	Receiver       string     `json:"receiver,omitempty"`
	Exported       bool       `json:"exported"`
	Location       location   `json:"location"`
	LineCount      int        `json:"line_count"`
	Doc            string     `json:"doc,omitempty"`
	Callsites      []callsite `json:"callsites"`
	CallsiteCounts counts     `json:"callsite_counts"`
}

type location struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

type callsite struct {
	FromPackage string `json:"from_package"`
	FromFile    string `json:"from_file"`
	FromFunc    string `json:"from_func"`
	Line        int    `json:"line"`
	Kind        string `json:"kind"` // "internal", "external", "test"
	CallExpr    string `json:"call_expr"`
}

type counts struct {
	Total    int `json:"total"`
	Internal int `json:"internal"` // same package, non-test
	External int `json:"external"` // different package, non-test
	Test     int `json:"test"`     // any _test.go file
}

type stats struct {
	ExportedFuncs         int `json:"exported_funcs"`
	UnexportedFuncs       int `json:"unexported_funcs"`
	ExportedWithZeroCalls int `json:"exported_with_zero_calls"`
	PossibleDeadCode      int `json:"possible_dead_code"`
}

// ---------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------

func main() {
	pkgFlag := flag.String("pkg", "", "Target package path relative to repo root (required)")
	outDirFlag := flag.String("outdir", "", "Output directory (default: coverage/report/graphs/<pkg>)")
	flag.Parse()

	if *pkgFlag == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -pkg is required")
		flag.Usage()
		os.Exit(1)
	}

	if err := run(*pkgFlag, *outDirFlag); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run(targetRel, outDir string) error {
	if _, err := os.Stat("go.mod"); err != nil {
		return fmt.Errorf("run from repo root (go.mod not found)")
	}

	module, err := readModule()
	if err != nil {
		return err
	}
	targetFull := module + "/" + strings.TrimSuffix(targetRel, "/")

	if outDir == "" {
		slug := strings.ReplaceAll(targetRel, "/", "-")
		outDir = filepath.Join("coverage", "report", "graphs", slug)
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	fmt.Printf("Loading packages from module %s ...\n", module)

	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedImports |
			packages.NeedDeps |
			packages.NeedTypes |
			packages.NeedSyntax |
			packages.NeedTypesInfo |
			packages.NeedModule,
		Tests: true, // include _test.go files in the loaded set
	}

	// Load every package in the module. "./..." is the magic pattern.
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return fmt.Errorf("load packages: %w", err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		return fmt.Errorf("%d package load errors (see above)", n)
	}

	fmt.Printf("  loaded %d packages\n", len(pkgs))

	// Locate target package among loaded set. Match by path.
	var target *packages.Package
	for _, p := range pkgs {
		if p.PkgPath == targetFull {
			target = p
			break
		}
	}
	if target == nil {
		// Try with tests variant
		for _, p := range pkgs {
			if p.PkgPath == targetFull+".test" || strings.HasSuffix(p.PkgPath, targetFull+"_test") {
				continue
			}
			if p.PkgPath == targetFull {
				target = p
				break
			}
		}
	}
	if target == nil {
		available := []string{}
		for _, p := range pkgs {
			if strings.HasPrefix(p.PkgPath, module) {
				available = append(available, p.PkgPath)
			}
		}
		sort.Strings(available)
		return fmt.Errorf("target package %q not found among loaded. Available:\n  %s",
			targetFull, strings.Join(available, "\n  "))
	}

	fmt.Printf("Target: %s (%d syntax files)\n", target.PkgPath, len(target.Syntax))

	// Phase 1: collect functions in the target package.
	rep := &report{
		Module:         module,
		TargetPkg:      target.PkgPath,
		TargetRel:      targetRel,
		PackagesLoaded: len(pkgs),
	}
	fnByObj := map[types.Object]*functionRecord{} // target function object → record

	for _, file := range target.Syntax {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			obj := target.TypesInfo.ObjectOf(fn.Name)
			if obj == nil {
				continue
			}
			rec := buildFunctionRecord(fn, obj, target)
			rep.Functions = append(rep.Functions, *rec)
			// Re-add pointer via index so we can accumulate callsites.
			fnByObj[obj] = &rep.Functions[len(rep.Functions)-1]
		}
	}

	// Phase 2: scan every loaded package for callsites of our target functions.
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		scanPackageForCallsites(p, fnByObj, module, target.PkgPath)
	}

	// Phase 3: stats + sorting
	for i := range rep.Functions {
		rec := &rep.Functions[i]
		sort.Slice(rec.Callsites, func(a, b int) bool {
			if rec.Callsites[a].FromFile != rec.Callsites[b].FromFile {
				return rec.Callsites[a].FromFile < rec.Callsites[b].FromFile
			}
			return rec.Callsites[a].Line < rec.Callsites[b].Line
		})
		rec.CallsiteCounts = countByKind(rec.Callsites)

		if rec.Exported {
			rep.Stats.ExportedFuncs++
			if rec.CallsiteCounts.Total == 0 {
				rep.Stats.ExportedWithZeroCalls++
			}
		} else {
			rep.Stats.UnexportedFuncs++
			if rec.CallsiteCounts.Total == 0 {
				rep.Stats.PossibleDeadCode++
			}
		}
	}

	sort.Slice(rep.Functions, func(i, j int) bool {
		return rep.Functions[i].Name < rep.Functions[j].Name
	})

	// Write outputs
	if err := writeJSON(filepath.Join(outDir, "callgraph.json"), rep); err != nil {
		return err
	}
	if err := writeCallgraphMarkdown(filepath.Join(outDir, "callgraph.md"), rep); err != nil {
		return err
	}
	if err := writeSignatureMarkdown(filepath.Join(outDir, "signature.md"), rep); err != nil {
		return err
	}

	fmt.Printf("\nWrote:\n")
	fmt.Printf("  %s\n", filepath.Join(outDir, "signature.md"))
	fmt.Printf("  %s\n", filepath.Join(outDir, "callgraph.md"))
	fmt.Printf("  %s\n", filepath.Join(outDir, "callgraph.json"))
	fmt.Printf("\nSummary for %s:\n", target.PkgPath)
	fmt.Printf("  exported functions:           %d\n", rep.Stats.ExportedFuncs)
	fmt.Printf("  unexported functions:         %d\n", rep.Stats.UnexportedFuncs)
	fmt.Printf("  exported with zero callers:   %d\n", rep.Stats.ExportedWithZeroCalls)
	fmt.Printf("  unexported with zero callers: %d\n", rep.Stats.PossibleDeadCode)
	return nil
}

// ---------------------------------------------------------------------
// Function record construction
// ---------------------------------------------------------------------

func buildFunctionRecord(fn *ast.FuncDecl, obj types.Object, p *packages.Package) *functionRecord {
	pos := p.Fset.Position(fn.Pos())
	endPos := p.Fset.Position(fn.End())

	rec := &functionRecord{
		Name:     fn.Name.Name,
		Exported: fn.Name.IsExported(),
		Location: location{File: pos.Filename, Line: pos.Line},
	}

	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		rec.IsMethod = true
		rec.Receiver = types.ExprString(fn.Recv.List[0].Type)
	}

	rec.Signature = signatureString(obj)
	rec.LineCount = endPos.Line - pos.Line + 1
	if fn.Doc != nil {
		rec.Doc = strings.TrimSpace(fn.Doc.Text())
	}

	return rec
}

func signatureString(obj types.Object) string {
	// Use types package to format the signature canonically.
	return types.ObjectString(obj, func(p *types.Package) string {
		// Qualify everything by short package name
		return p.Name()
	})
}

// ---------------------------------------------------------------------
// Callsite scanning
// ---------------------------------------------------------------------

// scanPackageForCallsites walks every CallExpr in pkg and, when the
// call resolves to a function in our target set, appends a callsite
// record to that function.
func scanPackageForCallsites(
	pkg *packages.Package,
	fnByObj map[types.Object]*functionRecord,
	module string,
	targetPkgPath string,
) {
	for _, file := range pkg.Syntax {
		// Find enclosing function for each CallExpr we visit.
		var enclosing string
		ast.Inspect(file, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok {
				enclosing = fn.Name.Name
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			// Use type info to resolve the callee.
			var calleeObj types.Object
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				calleeObj = pkg.TypesInfo.ObjectOf(fun)
			case *ast.SelectorExpr:
				calleeObj = pkg.TypesInfo.ObjectOf(fun.Sel)
			default:
				return true
			}
			if calleeObj == nil {
				return true
			}

			rec, tracked := fnByObj[calleeObj]
			if !tracked {
				return true
			}

			pos := pkg.Fset.Position(call.Pos())
			kind := classifyCallsite(pkg, pos.Filename, targetPkgPath)
			cs := callsite{
				FromPackage: pkg.PkgPath,
				FromFile:    pos.Filename,
				FromFunc:    enclosing,
				Line:        pos.Line,
				Kind:        kind,
				CallExpr:    formatCallExpr(call, pkg.Fset),
			}
			rec.Callsites = append(rec.Callsites, cs)
			return true
		})
	}
}

func classifyCallsite(pkg *packages.Package, filename, targetPkgPath string) string {
	if strings.HasSuffix(filename, "_test.go") {
		return "test"
	}
	if pkg.PkgPath == targetPkgPath {
		return "internal"
	}
	return "external"
}

func formatCallExpr(call *ast.CallExpr, fset *token.FileSet) string {
	// Reconstruct approximate source: "name(args...)"
	fn := ""
	switch f := call.Fun.(type) {
	case *ast.Ident:
		fn = f.Name
	case *ast.SelectorExpr:
		fn = types.ExprString(f.X) + "." + f.Sel.Name
	default:
		fn = types.ExprString(call.Fun)
	}
	return fn + "(...)"
}

func countByKind(cs []callsite) counts {
	var c counts
	for _, x := range cs {
		c.Total++
		switch x.Kind {
		case "internal":
			c.Internal++
		case "external":
			c.External++
		case "test":
			c.Test++
		}
	}
	return c
}

// ---------------------------------------------------------------------
// Output writers
// ---------------------------------------------------------------------

func writeJSON(path string, r *report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func writeSignatureMarkdown(path string, r *report) error {
	var sb strings.Builder
	p := func(s string, args ...interface{}) { fmt.Fprintf(&sb, s+"\n", args...) }

	p("# Package signature: `%s`", r.TargetPkg)
	p("")
	p("- Packages loaded (for callsite resolution): %d", r.PackagesLoaded)
	p("- Exported functions: %d", r.Stats.ExportedFuncs)
	p("- Unexported functions: %d", r.Stats.UnexportedFuncs)
	p("- Exported with zero callers: %d", r.Stats.ExportedWithZeroCalls)
	p("- Unexported with zero callers (possible dead code): %d", r.Stats.PossibleDeadCode)
	p("")

	// Exported first, then unexported.
	p("## Exported functions")
	p("")
	for _, fn := range r.Functions {
		if !fn.Exported {
			continue
		}
		emitFuncSignature(&sb, fn)
	}

	p("## Unexported functions")
	p("")
	for _, fn := range r.Functions {
		if fn.Exported {
			continue
		}
		emitFuncSignature(&sb, fn)
	}

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

func emitFuncSignature(sb *strings.Builder, fn functionRecord) {
	p := func(s string, args ...interface{}) { fmt.Fprintf(sb, s+"\n", args...) }
	name := fn.Name
	if fn.IsMethod {
		name = "(" + fn.Receiver + ")." + fn.Name
	}
	p("### `%s`", name)
	p("")
	p("- Signature: `%s`", fn.Signature)
	p("- Location: `%s:%d`", fn.Location.File, fn.Location.Line)
	p("- Lines: %d", fn.LineCount)
	p("- Callers: %d total (%d internal, %d external, %d test)",
		fn.CallsiteCounts.Total,
		fn.CallsiteCounts.Internal,
		fn.CallsiteCounts.External,
		fn.CallsiteCounts.Test)
	if fn.CallsiteCounts.Total == 0 {
		if fn.Exported {
			p("- ⚠️ Zero callers detected anywhere (unused export)")
		} else {
			p("- ⚠️ Zero callers — possible dead code")
		}
	}
	if fn.Doc != "" {
		p("")
		p("> %s", truncate(fn.Doc, 300))
	}
	p("")
}

func writeCallgraphMarkdown(path string, r *report) error {
	var sb strings.Builder
	p := func(s string, args ...interface{}) { fmt.Fprintf(&sb, s+"\n", args...) }

	p("# Call graph for `%s`", r.TargetPkg)
	p("")
	p("_Generated from type-resolved AST. Every callsite is verified by Go's type checker — no string matching ambiguity._")
	p("")

	// Group: functions with callers, functions without.
	var withCallers, withoutCallers []functionRecord
	for _, fn := range r.Functions {
		if fn.CallsiteCounts.Total > 0 {
			withCallers = append(withCallers, fn)
		} else {
			withoutCallers = append(withoutCallers, fn)
		}
	}

	// Sort withCallers by total descending (most-used first).
	sort.Slice(withCallers, func(i, j int) bool {
		return withCallers[i].CallsiteCounts.Total > withCallers[j].CallsiteCounts.Total
	})

	p("## Functions with callers (%d)", len(withCallers))
	p("")
	for _, fn := range withCallers {
		emitCallgraphFunc(&sb, fn)
	}

	if len(withoutCallers) > 0 {
		p("## Functions with ZERO callers (%d)", len(withoutCallers))
		p("")
		p("_For exported functions: unused public API._")
		p("_For unexported functions: possible dead code._")
		p("")
		for _, fn := range withoutCallers {
			exportedLabel := "unexported"
			if fn.Exported {
				exportedLabel = "exported"
			}
			name := fn.Name
			if fn.IsMethod {
				name = "(" + fn.Receiver + ")." + fn.Name
			}
			p("- `%s` (%s, at `%s:%d`)", name, exportedLabel, fn.Location.File, fn.Location.Line)
		}
		p("")
	}

	// Cross-package caller summary: which other packages depend on this one?
	p("## Caller packages (cross-SDK dependency)")
	p("")
	callerPkgs := map[string]int{}
	for _, fn := range r.Functions {
		for _, cs := range fn.Callsites {
			if cs.Kind == "external" {
				callerPkgs[cs.FromPackage]++
			}
		}
	}
	if len(callerPkgs) == 0 {
		p("_No external callers detected._")
	} else {
		type entry struct {
			pkg   string
			count int
		}
		var list []entry
		for k, v := range callerPkgs {
			list = append(list, entry{k, v})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].count > list[j].count })
		p("| Caller package | Callsites |")
		p("|----------------|----------:|")
		for _, e := range list {
			p("| `%s` | %d |", e.pkg, e.count)
		}
	}
	p("")

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

func emitCallgraphFunc(sb *strings.Builder, fn functionRecord) {
	p := func(s string, args ...interface{}) { fmt.Fprintf(sb, s+"\n", args...) }
	name := fn.Name
	if fn.IsMethod {
		name = "(" + fn.Receiver + ")." + fn.Name
	}
	p("### `%s`", name)
	p("")
	p("- Definition: `%s:%d`", fn.Location.File, fn.Location.Line)
	p("- Callers: **%d total** (%d internal, %d external, %d test)",
		fn.CallsiteCounts.Total,
		fn.CallsiteCounts.Internal,
		fn.CallsiteCounts.External,
		fn.CallsiteCounts.Test)
	p("")
	if len(fn.Callsites) == 0 {
		p("_No callsites._")
		p("")
		return
	}
	p("| From | In function | Line | Kind | Call |")
	p("|------|-------------|-----:|------|------|")
	for _, cs := range fn.Callsites {
		fromFunc := cs.FromFunc
		if fromFunc == "" {
			fromFunc = "(top-level)"
		}
		p("| `%s` | `%s` | %d | %s | `%s` |",
			shortFile(cs.FromFile), fromFunc, cs.Line, cs.Kind, cs.CallExpr)
	}
	p("")
}

func shortFile(path string) string {
	// Strip leading absolute-path cruft; make repo-relative if possible
	cwd, err := os.Getwd()
	if err == nil && strings.HasPrefix(path, cwd+"/") {
		return path[len(cwd)+1:]
	}
	return path
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

func readModule() (string, error) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(line[len("module "):]), nil
		}
	}
	return "", fmt.Errorf("module directive not found in go.mod")
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
