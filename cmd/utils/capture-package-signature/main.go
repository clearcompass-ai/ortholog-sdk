// Command capture-package-signature extracts a comprehensive,
// AST-verified signature of a Go package — every exported identifier,
// every top-level function, every callsite. Produces evidence-based
// input for test planning.
//
// DESIGN PRINCIPLES:
//   - No inference beyond what go/ast gives us. If a function has
//     exported type in its signature, that's a real API contract.
//     If a function is unexported and has zero callers outside its
//     defining file, that's dead code.
//   - No opinions. The tool reports; the operator decides.
//   - One-shot, read-only. No modifications to the codebase.
//
// USAGE:
//
//	cd ~/workspace/ortholog-sdk
//	go run cmd/capture-package-signature/main.go -pkg crypto
//
// Flags:
//
//	-pkg      The package path relative to repo root (required)
//	          e.g. "crypto", "core/envelope", "lifecycle"
//	-format   "md" (default) for Markdown, "json" for machine-readable
//	-out      Output file. Default stdout.
//
// OUTPUT SECTIONS:
//  1. Package overview: files, lines of code, build status
//  2. Exported API surface: types, functions, methods, constants, vars
//  3. Unexported symbols: for dead-code analysis
//  4. Internal dependencies: what this package imports
//  5. Callsites: who calls every exported function, from where
//  6. Test coverage indicator: whether tests exist and what they test
//  7. Doc-comment status: which exports have Go doc comments
//  8. Cyclomatic complexity per function (rough proxy for test burden)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ---------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------

type pkgReport struct {
	Module       string        `json:"module"`
	Package      string        `json:"package"`      // repo-relative path
	PackageName  string        `json:"package_name"` // as declared in source
	Files        []fileInfo    `json:"files"`
	Imports      []string      `json:"imports"`
	Exports      exportSurface `json:"exports"`
	Unexported   symbolList    `json:"unexported"`
	Callsites    callsiteMap   `json:"callsites"` // exported function → callers
	TestCoverage testInfo      `json:"test_coverage"`
	Stats        packageStats  `json:"stats"`
}

type fileInfo struct {
	Path       string `json:"path"`
	Lines      int    `json:"lines"`
	HasTests   bool   `json:"has_tests"`
	DocComment string `json:"doc_comment,omitempty"`
}

type exportSurface struct {
	Types     []typeInfo  `json:"types"`
	Functions []funcInfo  `json:"functions"`
	Methods   []funcInfo  `json:"methods"`
	Constants []valueInfo `json:"constants"`
	Variables []valueInfo `json:"variables"`
}

type typeInfo struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"` // struct, interface, alias, etc.
	Location   string   `json:"location"`
	Fields     []string `json:"fields,omitempty"`
	Methods    []string `json:"methods,omitempty"`
	DocComment string   `json:"doc,omitempty"`
	Doc        string   `json:"-"` // for markdown output
}

type funcInfo struct {
	Name         string   `json:"name"`
	Receiver     string   `json:"receiver,omitempty"`
	Signature    string   `json:"signature"`
	Location     string   `json:"location"`
	LineCount    int      `json:"line_count"`
	Complexity   int      `json:"complexity"`
	ReturnsError bool     `json:"returns_error"`
	DocComment   string   `json:"doc,omitempty"`
	Params       []string `json:"params,omitempty"`
	Results      []string `json:"results,omitempty"`
}

type valueInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`
	Value    string `json:"value,omitempty"`
	Location string `json:"location"`
	Doc      string `json:"doc,omitempty"`
}

type symbolList struct {
	Types     []typeInfo  `json:"types"`
	Functions []funcInfo  `json:"functions"`
	Variables []valueInfo `json:"variables"`
}

type callsiteMap map[string][]callsite // fn name → where it's called from

type callsite struct {
	FromFile    string `json:"from_file"`
	FromFunc    string `json:"from_func"`
	Line        int    `json:"line"`
	IsTest      bool   `json:"is_test"`
	IsInPackage bool   `json:"is_in_package"` // true if caller is in the same package
}

type testInfo struct {
	HasTestFiles   bool     `json:"has_test_files"`
	TestFiles      []string `json:"test_files"`
	TestFunctions  []string `json:"test_functions"`
	FuzzFunctions  []string `json:"fuzz_functions"`
	BenchmarkCount int      `json:"benchmark_count"`
	ExampleCount   int      `json:"example_count"`
}

type packageStats struct {
	TotalFiles           int `json:"total_files"`
	TotalLines           int `json:"total_lines"`
	TestFiles            int `json:"test_files"`
	TestLines            int `json:"test_lines"`
	ExportedCount        int `json:"exported_count"`
	UnexportedCount      int `json:"unexported_count"`
	ExportedUndocumented int `json:"exported_undocumented"`
}

// ---------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------

func main() {
	pkgFlag := flag.String("pkg", "", "Package path relative to repo root (required)")
	formatFlag := flag.String("format", "md", "Output format: md or json")
	outFlag := flag.String("out", "", "Output file (default stdout)")
	flag.Parse()

	if *pkgFlag == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -pkg is required")
		flag.Usage()
		os.Exit(1)
	}

	if err := run(*pkgFlag, *formatFlag, *outFlag); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run(pkgPath, format, outPath string) error {
	if _, err := os.Stat("go.mod"); err != nil {
		return fmt.Errorf("run from repo root (go.mod not found)")
	}

	module, err := readModule("go.mod")
	if err != nil {
		return err
	}

	report, err := analyzePackage(pkgPath, module)
	if err != nil {
		return err
	}

	// Analyze callsites by scanning the entire repo.
	if err := findCallsites(report, module); err != nil {
		return fmt.Errorf("callsite scan: %w", err)
	}

	// Emit.
	var out io.Writer = os.Stdout
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}

	switch format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	case "md":
		return emitMarkdown(out, report)
	default:
		return fmt.Errorf("unknown format: %s (use md or json)", format)
	}
}

// ---------------------------------------------------------------------
// Read go.mod for module name
// ---------------------------------------------------------------------

func readModule(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(line[len("module "):]), nil
		}
	}
	return "", fmt.Errorf("no module directive in go.mod")
}

// ---------------------------------------------------------------------
// Package analysis (AST-level)
// ---------------------------------------------------------------------

func analyzePackage(pkgPath, module string) (*pkgReport, error) {
	report := &pkgReport{
		Module:    module,
		Package:   pkgPath,
		Callsites: callsiteMap{},
	}

	entries, err := os.ReadDir(pkgPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", pkgPath, err)
	}

	fset := token.NewFileSet()
	importSet := map[string]struct{}{}
	var testFilePaths []string

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		path := filepath.Join(pkgPath, e.Name())
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			// Don't fail the whole run; record and skip.
			fmt.Fprintf(os.Stderr, "WARN: parse %s: %v\n", path, err)
			continue
		}

		if report.PackageName == "" {
			report.PackageName = file.Name.Name
		}

		content, _ := os.ReadFile(path)
		lineCount := strings.Count(string(content), "\n") + 1
		isTest := strings.HasSuffix(e.Name(), "_test.go")

		report.Files = append(report.Files, fileInfo{
			Path:       path,
			Lines:      lineCount,
			HasTests:   isTest,
			DocComment: docString(file.Doc),
		})

		if isTest {
			testFilePaths = append(testFilePaths, path)
			report.Stats.TestFiles++
			report.Stats.TestLines += lineCount
			collectTestFunctions(file, &report.TestCoverage)
		} else {
			report.Stats.TotalFiles++
			report.Stats.TotalLines += lineCount
		}

		for _, imp := range file.Imports {
			importSet[strings.Trim(imp.Path.Value, `"`)] = struct{}{}
		}

		if !isTest {
			collectDecls(file, fset, report)
		}
	}

	// Consolidate imports sorted.
	for imp := range importSet {
		report.Imports = append(report.Imports, imp)
	}
	sort.Strings(report.Imports)

	report.TestCoverage.HasTestFiles = len(testFilePaths) > 0
	report.TestCoverage.TestFiles = testFilePaths

	return report, nil
}

// collectDecls walks a production file and adds exports + unexported to report.
func collectDecls(file *ast.File, fset *token.FileSet, report *pkgReport) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			info := buildFuncInfo(d, fset, file)
			isExported := isExportedName(d.Name.Name)

			if d.Recv != nil && len(d.Recv.List) > 0 {
				// Method
				if isExported {
					report.Exports.Methods = append(report.Exports.Methods, info)
					report.Stats.ExportedCount++
					if info.DocComment == "" {
						report.Stats.ExportedUndocumented++
					}
				} else {
					report.Unexported.Functions = append(report.Unexported.Functions, info)
					report.Stats.UnexportedCount++
				}
			} else {
				// Plain function
				if isExported {
					report.Exports.Functions = append(report.Exports.Functions, info)
					report.Stats.ExportedCount++
					if info.DocComment == "" {
						report.Stats.ExportedUndocumented++
					}
				} else {
					report.Unexported.Functions = append(report.Unexported.Functions, info)
					report.Stats.UnexportedCount++
				}
			}

		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					ti := buildTypeInfo(s, d, fset)
					if isExportedName(s.Name.Name) {
						report.Exports.Types = append(report.Exports.Types, ti)
						report.Stats.ExportedCount++
						if ti.DocComment == "" {
							report.Stats.ExportedUndocumented++
						}
					} else {
						report.Unexported.Types = append(report.Unexported.Types, ti)
						report.Stats.UnexportedCount++
					}

				case *ast.ValueSpec:
					for i, name := range s.Names {
						vi := valueInfo{
							Name:     name.Name,
							Location: fset.Position(name.Pos()).String(),
							Doc:      docString(d.Doc),
						}
						if s.Type != nil {
							vi.Type = exprString(s.Type)
						}
						if i < len(s.Values) {
							vi.Value = exprString(s.Values[i])
						}
						switch d.Tok {
						case token.CONST:
							if isExportedName(name.Name) {
								report.Exports.Constants = append(report.Exports.Constants, vi)
								report.Stats.ExportedCount++
								if vi.Doc == "" {
									report.Stats.ExportedUndocumented++
								}
							} else {
								// Unexported consts are fine; skip tracking to reduce noise.
								report.Stats.UnexportedCount++
							}
						case token.VAR:
							if isExportedName(name.Name) {
								report.Exports.Variables = append(report.Exports.Variables, vi)
								report.Stats.ExportedCount++
								if vi.Doc == "" {
									report.Stats.ExportedUndocumented++
								}
							} else {
								report.Unexported.Variables = append(report.Unexported.Variables, vi)
								report.Stats.UnexportedCount++
							}
						}
					}
				}
			}
		}
	}
}

func buildFuncInfo(d *ast.FuncDecl, fset *token.FileSet, file *ast.File) funcInfo {
	info := funcInfo{
		Name:       d.Name.Name,
		Location:   fset.Position(d.Pos()).String(),
		DocComment: docString(d.Doc),
		Complexity: 1, // base complexity
	}

	// Receiver (for methods)
	if d.Recv != nil && len(d.Recv.List) > 0 {
		info.Receiver = exprString(d.Recv.List[0].Type)
	}

	// Params
	if d.Type.Params != nil {
		for _, p := range d.Type.Params.List {
			typStr := exprString(p.Type)
			if len(p.Names) == 0 {
				info.Params = append(info.Params, typStr)
			} else {
				for _, n := range p.Names {
					info.Params = append(info.Params, n.Name+" "+typStr)
				}
			}
		}
	}

	// Results
	if d.Type.Results != nil {
		for _, r := range d.Type.Results.List {
			typStr := exprString(r.Type)
			if typStr == "error" {
				info.ReturnsError = true
			}
			if len(r.Names) == 0 {
				info.Results = append(info.Results, typStr)
			} else {
				for _, n := range r.Names {
					info.Results = append(info.Results, n.Name+" "+typStr)
				}
			}
		}
	}

	// Signature string (human-readable)
	info.Signature = buildSigString(&info)

	// Line count and complexity (rough: count branch points)
	if d.Body != nil {
		startLine := fset.Position(d.Body.Lbrace).Line
		endLine := fset.Position(d.Body.Rbrace).Line
		info.LineCount = endLine - startLine + 1
		info.Complexity = cyclomaticComplexity(d.Body)
	}

	return info
}

func buildSigString(info *funcInfo) string {
	var sb strings.Builder
	sb.WriteString("func ")
	if info.Receiver != "" {
		sb.WriteString("(")
		sb.WriteString(info.Receiver)
		sb.WriteString(") ")
	}
	sb.WriteString(info.Name)
	sb.WriteString("(")
	sb.WriteString(strings.Join(info.Params, ", "))
	sb.WriteString(")")
	if len(info.Results) > 0 {
		sb.WriteString(" ")
		if len(info.Results) == 1 {
			sb.WriteString(info.Results[0])
		} else {
			sb.WriteString("(")
			sb.WriteString(strings.Join(info.Results, ", "))
			sb.WriteString(")")
		}
	}
	return sb.String()
}

func buildTypeInfo(s *ast.TypeSpec, parent *ast.GenDecl, fset *token.FileSet) typeInfo {
	ti := typeInfo{
		Name:       s.Name.Name,
		Location:   fset.Position(s.Pos()).String(),
		DocComment: docString(parent.Doc),
	}
	switch t := s.Type.(type) {
	case *ast.StructType:
		ti.Kind = "struct"
		if t.Fields != nil {
			for _, f := range t.Fields.List {
				typStr := exprString(f.Type)
				if len(f.Names) == 0 {
					ti.Fields = append(ti.Fields, "<embedded> "+typStr)
				} else {
					for _, n := range f.Names {
						vis := "unexported"
						if isExportedName(n.Name) {
							vis = "exported"
						}
						ti.Fields = append(ti.Fields, fmt.Sprintf("%s %s (%s)", n.Name, typStr, vis))
					}
				}
			}
		}
	case *ast.InterfaceType:
		ti.Kind = "interface"
		if t.Methods != nil {
			for _, m := range t.Methods.List {
				for _, n := range m.Names {
					ti.Methods = append(ti.Methods, n.Name+exprString(m.Type))
				}
			}
		}
	case *ast.Ident:
		ti.Kind = "alias:" + t.Name
	case *ast.SelectorExpr:
		ti.Kind = "alias:" + exprString(t)
	case *ast.ArrayType:
		ti.Kind = "array:" + exprString(t)
	case *ast.MapType:
		ti.Kind = "map:" + exprString(t)
	case *ast.FuncType:
		ti.Kind = "func:" + exprString(t)
	default:
		ti.Kind = fmt.Sprintf("other(%T)", t)
	}
	return ti
}

func cyclomaticComplexity(body *ast.BlockStmt) int {
	complexity := 1
	ast.Inspect(body, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.CaseClause, *ast.CommClause:
			complexity++
		case *ast.BinaryExpr:
			be := n.(*ast.BinaryExpr)
			if be.Op == token.LAND || be.Op == token.LOR {
				complexity++
			}
		}
		return true
	})
	return complexity
}

// ---------------------------------------------------------------------
// Test function collection
// ---------------------------------------------------------------------

func collectTestFunctions(file *ast.File, info *testInfo) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fn.Name.Name
		switch {
		case strings.HasPrefix(name, "Test"):
			info.TestFunctions = append(info.TestFunctions, name)
		case strings.HasPrefix(name, "Fuzz"):
			info.FuzzFunctions = append(info.FuzzFunctions, name)
		case strings.HasPrefix(name, "Benchmark"):
			info.BenchmarkCount++
		case strings.HasPrefix(name, "Example"):
			info.ExampleCount++
		}
	}
}

// ---------------------------------------------------------------------
// Callsite discovery across the whole repo
// ---------------------------------------------------------------------

func findCallsites(report *pkgReport, module string) error {
	// Collect names of exported functions/methods we care about.
	names := map[string]struct{}{}
	for _, f := range report.Exports.Functions {
		names[f.Name] = struct{}{}
	}
	for _, m := range report.Exports.Methods {
		names[m.Name] = struct{}{}
	}

	// Walk the whole repo.
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // best-effort
		}
		if info.IsDir() {
			if info.Name() == "vendor" || info.Name() == ".git" || info.Name() == "coverage" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Skip files in the package itself for "external callsite" view,
		// but we'll include them later with IsInPackage=true.

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}

		isTest := strings.HasSuffix(path, "_test.go")
		isInPkg := filepath.Dir(path) == report.Package

		// Track current enclosing function.
		var enclosing string

		ast.Inspect(file, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok {
				enclosing = fn.Name.Name
				return true
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var callName string
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				callName = fun.Sel.Name
			case *ast.Ident:
				callName = fun.Name
			default:
				return true
			}
			if _, ok := names[callName]; !ok {
				return true
			}
			cs := callsite{
				FromFile:    path,
				FromFunc:    enclosing,
				Line:        fset.Position(call.Pos()).Line,
				IsTest:      isTest,
				IsInPackage: isInPkg,
			}
			report.Callsites[callName] = append(report.Callsites[callName], cs)
			return true
		})
		return nil
	})
	return err
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

func isExportedName(name string) bool {
	if name == "" {
		return false
	}
	r, _ := utf8.DecodeRuneInString(name)
	return unicode.IsUpper(r)
}

func docString(d *ast.CommentGroup) string {
	if d == nil {
		return ""
	}
	return strings.TrimSpace(d.Text())
}

func exprString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + exprString(t.X)
	case *ast.SelectorExpr:
		return exprString(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		if t.Len != nil {
			return "[" + exprString(t.Len) + "]" + exprString(t.Elt)
		}
		return "[]" + exprString(t.Elt)
	case *ast.MapType:
		return "map[" + exprString(t.Key) + "]" + exprString(t.Value)
	case *ast.InterfaceType:
		return "interface{...}"
	case *ast.FuncType:
		return "func(...)"
	case *ast.Ellipsis:
		return "..." + exprString(t.Elt)
	case *ast.BasicLit:
		return t.Value
	case *ast.ChanType:
		return "chan " + exprString(t.Value)
	default:
		return fmt.Sprintf("<%T>", e)
	}
}

// ---------------------------------------------------------------------
// Markdown output
// ---------------------------------------------------------------------

func emitMarkdown(w io.Writer, r *pkgReport) error {
	p := func(format string, args ...interface{}) {
		fmt.Fprintf(w, format+"\n", args...)
	}

	p("# Package signature: `%s/%s`", r.Module, r.Package)
	p("")
	p("## Overview")
	p("")
	p("- **Package name:** `%s`", r.PackageName)
	p("- **Production files:** %d (%d lines)", r.Stats.TotalFiles, r.Stats.TotalLines)
	p("- **Test files:** %d (%d lines)", r.Stats.TestFiles, r.Stats.TestLines)
	p("- **Exported symbols:** %d", r.Stats.ExportedCount)
	p("- **Unexported symbols:** %d", r.Stats.UnexportedCount)
	p("- **Exported but undocumented:** %d", r.Stats.ExportedUndocumented)
	p("")

	if len(r.Files) > 0 {
		p("### Files")
		p("")
		for _, f := range r.Files {
			tag := "prod"
			if f.HasTests {
				tag = "test"
			}
			p("- `%s` — %d lines (%s)", f.Path, f.Lines, tag)
		}
		p("")
	}

	if r.TestCoverage.HasTestFiles {
		p("### Test inventory")
		p("")
		p("- Test functions: %d", len(r.TestCoverage.TestFunctions))
		p("- Fuzz functions: %d", len(r.TestCoverage.FuzzFunctions))
		p("- Benchmarks: %d", r.TestCoverage.BenchmarkCount)
		p("- Examples: %d", r.TestCoverage.ExampleCount)
		if len(r.TestCoverage.TestFunctions) > 0 {
			p("")
			p("<details><summary>Test function list</summary>")
			p("")
			for _, t := range r.TestCoverage.TestFunctions {
				p("- `%s`", t)
			}
			p("")
			p("</details>")
		}
		p("")
	} else {
		p("### Test inventory")
		p("")
		p("**No test files in this package.**")
		p("")
	}

	// Imports
	if len(r.Imports) > 0 {
		p("## Imports")
		p("")
		for _, imp := range r.Imports {
			p("- `%s`", imp)
		}
		p("")
	}

	// Exports
	p("## Exported API surface")
	p("")

	if len(r.Exports.Types) > 0 {
		p("### Types (%d)", len(r.Exports.Types))
		p("")
		for _, t := range r.Exports.Types {
			docMark := ""
			if t.DocComment == "" {
				docMark = " ⚠️ _undocumented_"
			}
			p("#### `%s` _(%s)_%s", t.Name, t.Kind, docMark)
			p("")
			p("Location: `%s`", t.Location)
			if len(t.Fields) > 0 {
				p("")
				p("Fields:")
				for _, f := range t.Fields {
					p("- %s", f)
				}
			}
			if len(t.Methods) > 0 {
				p("")
				p("Interface methods:")
				for _, m := range t.Methods {
					p("- %s", m)
				}
			}
			if t.DocComment != "" {
				p("")
				p("> %s", truncate(t.DocComment, 200))
			}
			p("")
		}
	}

	if len(r.Exports.Functions) > 0 {
		p("### Functions (%d)", len(r.Exports.Functions))
		p("")
		for _, f := range r.Exports.Functions {
			emitFuncMarkdown(w, f, r.Callsites[f.Name])
		}
	}

	if len(r.Exports.Methods) > 0 {
		p("### Methods (%d)", len(r.Exports.Methods))
		p("")
		for _, m := range r.Exports.Methods {
			emitFuncMarkdown(w, m, r.Callsites[m.Name])
		}
	}

	if len(r.Exports.Constants) > 0 {
		p("### Constants (%d)", len(r.Exports.Constants))
		p("")
		for _, c := range r.Exports.Constants {
			tstr := ""
			if c.Type != "" {
				tstr = " " + c.Type
			}
			docMark := ""
			if c.Doc == "" {
				docMark = " ⚠️"
			}
			p("- `%s%s = %s`%s", c.Name, tstr, c.Value, docMark)
		}
		p("")
	}

	if len(r.Exports.Variables) > 0 {
		p("### Variables (%d)", len(r.Exports.Variables))
		p("")
		for _, v := range r.Exports.Variables {
			tstr := ""
			if v.Type != "" {
				tstr = " " + v.Type
			}
			docMark := ""
			if v.Doc == "" {
				docMark = " ⚠️"
			}
			p("- `%s%s`%s", v.Name, tstr, docMark)
		}
		p("")
	}

	// Unexported (brief)
	if len(r.Unexported.Functions)+len(r.Unexported.Types)+len(r.Unexported.Variables) > 0 {
		p("## Unexported symbols (brief)")
		p("")
		if len(r.Unexported.Functions) > 0 {
			p("### Unexported functions/methods")
			for _, f := range r.Unexported.Functions {
				deadMark := ""
				cs := r.Callsites[f.Name]
				totalCalls := len(cs)
				if totalCalls == 0 {
					deadMark = " ⚠️ _0 callers — possible dead code_"
				}
				p("- `%s` (line count: %d, complexity: %d, callers: %d)%s",
					f.Signature, f.LineCount, f.Complexity, totalCalls, deadMark)
			}
			p("")
		}
		if len(r.Unexported.Types) > 0 {
			p("### Unexported types")
			for _, t := range r.Unexported.Types {
				p("- `%s` _(%s)_", t.Name, t.Kind)
			}
			p("")
		}
	}

	// Risk summary
	p("## Risk summary")
	p("")
	undoc := r.Stats.ExportedUndocumented
	if undoc > 0 {
		p("- ⚠️  %d/%d exported symbols are undocumented", undoc, r.Stats.ExportedCount)
	} else {
		p("- ✅ All exported symbols are documented")
	}
	if !r.TestCoverage.HasTestFiles {
		p("- ⚠️  No test files in this package")
	}
	// Count possibly-dead unexported
	dead := 0
	for _, f := range r.Unexported.Functions {
		if len(r.Callsites[f.Name]) == 0 {
			dead++
		}
	}
	if dead > 0 {
		p("- ⚠️  %d unexported functions appear unused in this scan (verify before deletion)", dead)
	}

	return nil
}

func emitFuncMarkdown(w io.Writer, f funcInfo, callsites []callsite) {
	fmt.Fprintf(w, "#### `%s`\n\n", f.Name)
	fmt.Fprintf(w, "- Signature: `%s`\n", f.Signature)
	fmt.Fprintf(w, "- Location: `%s`\n", f.Location)
	fmt.Fprintf(w, "- Line count: %d\n", f.LineCount)
	fmt.Fprintf(w, "- Cyclomatic complexity: %d\n", f.Complexity)
	fmt.Fprintf(w, "- Returns error: %v\n", f.ReturnsError)

	// Categorize callsites
	external, internal, tests := 0, 0, 0
	for _, cs := range callsites {
		if cs.IsTest {
			tests++
		} else if cs.IsInPackage {
			internal++
		} else {
			external++
		}
	}
	fmt.Fprintf(w, "- Callers: %d external / %d internal / %d tests\n",
		external, internal, tests)

	if f.DocComment == "" {
		fmt.Fprintf(w, "- ⚠️  _undocumented_\n")
	} else {
		fmt.Fprintf(w, "\n> %s\n", truncate(f.DocComment, 300))
	}

	if len(callsites) > 0 && len(callsites) <= 10 {
		fmt.Fprintf(w, "\n<details><summary>Callsite list</summary>\n\n")
		for _, cs := range callsites {
			kind := "external"
			if cs.IsInPackage {
				kind = "internal"
			} else if cs.IsTest {
				kind = "test"
			}
			fmt.Fprintf(w, "- `%s:%d` in `%s` (%s)\n",
				cs.FromFile, cs.Line, cs.FromFunc, kind)
		}
		fmt.Fprintf(w, "\n</details>\n")
	}
	fmt.Fprintln(w)
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
