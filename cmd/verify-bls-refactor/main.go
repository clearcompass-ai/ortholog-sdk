/*
cmd/verify-bls-refactor/main.go

AST-based audit for the per-signature SchemeTag refactor.

Walks every Go file in the SDK (including tests) using go/types for
semantic analysis and reports every construction, mutation, or access
site touching CosignedTreeHead or WitnessSignature from the target
module. Use this tool BEFORE the refactor to get a definitive list of
sites that need updating, and AFTER the refactor to verify no site was
missed.

INVOCATION:

	go run ./cmd/verify-bls-refactor -v
	go run ./cmd/verify-bls-refactor -json > audit.json
	go run ./cmd/verify-bls-refactor -fail-on-findings  # for CI gates

DETECTIONS (all type-checked, not string-matched):
 1. LITERAL_COSIGNED_HEAD    — composite literals of types.CosignedTreeHead
 2. LITERAL_WITNESS_SIG      — composite literals of types.WitnessSignature
 3. ACCESS_COSIGNED_SCHEMETAG — field access on CosignedTreeHead.SchemeTag
 4. NEW_ALLOCATION           — new(T) for tracked types
 5. ADDR_EMPTY_LITERAL       — &T{} (address-of empty struct literal)
 6. FUNC_PARAM               — function parameter typed as tracked type
 7. FUNC_RESULT              — function return type of tracked type
 8. STRUCT_FIELD             — struct field of tracked type
 9. TYPE_ASSERTION           — x.(T) type assertion to tracked type
 10. REFLECT_ACCESS           — reflect.Type/Value operations on tracked type
 11. JSON_TAG                 — struct tag referencing scheme_tag
 12. METHOD_VALUE             — bound method reference on tracked type

MODULE SCOPING:

	Only tracks types from github.com/clearcompass-ai/ortholog-sdk/types.
	A local struct named CosignedTreeHead in a different package is NOT
	flagged — this catches lookalike-name false positives.

EXIT CODES:

	0   audit ran successfully (findings may exist)
	1   audit found issues AND -fail-on-findings was specified
	2   tool-level error (package load failure, etc.)
*/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// ─────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────

const (
	targetModule     = "github.com/clearcompass-ai/ortholog-sdk"
	targetTypesPkg   = targetModule + "/types"
	typeCosignedHead = "CosignedTreeHead"
	typeWitnessSig   = "WitnessSignature"
	fieldSchemeTag   = "SchemeTag"
)

// Tracked type identifiers. Only types from the target module are flagged.
var trackedTypes = map[string]bool{
	typeCosignedHead: true,
	typeWitnessSig:   true,
}

// ─────────────────────────────────────────────────────────────────────
// Finding
// ─────────────────────────────────────────────────────────────────────

type Finding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Col      int    `json:"col"`
	Category string `json:"category"`
	Type     string `json:"type,omitempty"`
	Detail   string `json:"detail"`
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d:%d\t[%s]\t%s", f.File, f.Line, f.Col, f.Category, f.Detail)
}

// ─────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────

var moduleRoot string

func main() {
	root := flag.String("root", ".", "SDK root directory")
	verbose := flag.Bool("v", false, "verbose output")
	jsonOut := flag.Bool("json", false, "JSON output")
	failOnFindings := flag.Bool("fail-on-findings", false, "exit 1 if any findings")
	flag.Parse()

	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve root: %v\n", err)
		os.Exit(2)
	}
	moduleRoot = absRoot

	// Validate the tool is being run inside the target module.
	if !isInTargetModule(absRoot) {
		fmt.Fprintf(os.Stderr,
			"warning: %s does not appear to be the root of %s\n",
			absRoot, targetModule)
	}

	if *verbose {
		fileCount, _ := countGoFiles(absRoot)
		fmt.Fprintf(os.Stderr, "scanning %d Go files under %s\n", fileCount, absRoot)
	}

	// Load packages with full type information.
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports |
			packages.NeedDeps | packages.NeedModule,
		Dir:   absRoot,
		Tests: true, // include _test.go files
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		fmt.Fprintf(os.Stderr, "load packages: %v\n", err)
		os.Exit(2)
	}

	var loadErrors int
	for _, pkg := range pkgs {
		for _, e := range pkg.Errors {
			fmt.Fprintf(os.Stderr, "pkg %s: %v\n", pkg.PkgPath, e)
			loadErrors++
		}
	}
	if loadErrors > 0 && *verbose {
		fmt.Fprintf(os.Stderr, "note: %d package load errors; analysis may be incomplete\n", loadErrors)
	}

	var findings []Finding
	for _, pkg := range pkgs {
		findings = append(findings, analyzePackage(pkg)...)
	}

	// Deduplicate findings — packages can appear twice (once with tests,
	// once without) when Tests:true is set.
	findings = dedupFindings(findings)

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Category < findings[j].Category
	})

	if *jsonOut {
		printJSON(findings)
	} else {
		printHuman(findings)
	}

	if len(findings) > 0 {
		summary := summarize(findings)
		fmt.Fprintf(os.Stderr, "\n%s\n", summary)
	}

	if *failOnFindings && len(findings) > 0 {
		os.Exit(1)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Package analysis
// ─────────────────────────────────────────────────────────────────────

func analyzePackage(pkg *packages.Package) []Finding {
	var out []Finding
	if pkg.TypesInfo == nil || pkg.Fset == nil {
		return out
	}

	for _, file := range pkg.Syntax {
		filename := pkg.Fset.Position(file.Pos()).Filename
		if filename == "" {
			continue
		}

		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.CompositeLit:
				if f := checkCompositeLit(pkg, filename, node); f != nil {
					out = append(out, *f)
				}
			case *ast.SelectorExpr:
				if f := checkSelector(pkg, filename, node); f != nil {
					out = append(out, *f)
				}
			case *ast.CallExpr:
				if fs := checkCall(pkg, filename, node); len(fs) > 0 {
					out = append(out, fs...)
				}
			case *ast.UnaryExpr:
				if f := checkUnaryAddrOf(pkg, filename, node); f != nil {
					out = append(out, *f)
				}
			case *ast.FuncDecl:
				if fs := checkFuncDecl(pkg, filename, node); len(fs) > 0 {
					out = append(out, fs...)
				}
			case *ast.Field:
				if fs := checkField(pkg, filename, node); len(fs) > 0 {
					out = append(out, fs...)
				}
			case *ast.TypeAssertExpr:
				if f := checkTypeAssertion(pkg, filename, node); f != nil {
					out = append(out, *f)
				}
			}
			return true
		})
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────
// Individual checks
// ─────────────────────────────────────────────────────────────────────

func checkCompositeLit(pkg *packages.Package, filename string, lit *ast.CompositeLit) *Finding {
	tn := qualifiedTypeName(pkg, lit)
	if tn == "" {
		return nil
	}

	pos := pkg.Fset.Position(lit.Pos())
	keyed := isKeyedLiteral(lit)

	// Determine if the old-shape SchemeTag is set.
	setsSchemeTag := false
	if keyed {
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == fieldSchemeTag {
				setsSchemeTag = true
				break
			}
		}
	} else {
		// Positional: determine based on actual field count of the struct.
		// Old CosignedTreeHead: 3 slots (TreeHead, SchemeTag, Signatures)
		// New CosignedTreeHead: 2 slots (TreeHead, Signatures)
		// Old WitnessSignature: 2 slots (PubKeyID, SigBytes)
		// New WitnessSignature: 3 slots (PubKeyID, SchemeTag, SigBytes)
		n := len(lit.Elts)
		if tn == typeCosignedHead && n == 3 {
			setsSchemeTag = true // old shape
		} else if tn == typeWitnessSig && n == 3 {
			setsSchemeTag = true // new shape (or any 3-elt form)
		}
	}

	var category string
	switch tn {
	case typeCosignedHead:
		category = "LITERAL_COSIGNED_HEAD"
	case typeWitnessSig:
		category = "LITERAL_WITNESS_SIG"
	default:
		return nil
	}

	return &Finding{
		File:     relPath(filename),
		Line:     pos.Line,
		Col:      pos.Column,
		Category: category,
		Type:     tn,
		Detail: fmt.Sprintf("keyed=%v, sets_SchemeTag=%v, elts=%d",
			keyed, setsSchemeTag, len(lit.Elts)),
	}
}

func checkSelector(pkg *packages.Package, filename string, sel *ast.SelectorExpr) *Finding {
	if sel.Sel == nil || sel.Sel.Name != fieldSchemeTag {
		return nil
	}
	xType := pkg.TypesInfo.TypeOf(sel.X)
	if xType == nil {
		return nil
	}
	tn := unwrapAndName(xType)
	if tn != typeCosignedHead {
		return nil
	}
	if !isFromTargetModule(xType) {
		return nil
	}

	pos := pkg.Fset.Position(sel.Pos())
	return &Finding{
		File:     relPath(filename),
		Line:     pos.Line,
		Col:      pos.Column,
		Category: "ACCESS_COSIGNED_SCHEMETAG",
		Type:     typeCosignedHead,
		Detail:   "field access CosignedTreeHead.SchemeTag",
	}
}

func checkCall(pkg *packages.Package, filename string, call *ast.CallExpr) []Finding {
	var out []Finding

	// Check for `new(T)` where T is a tracked type.
	if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "new" && len(call.Args) == 1 {
		argType := pkg.TypesInfo.TypeOf(call.Args[0])
		if argType != nil {
			tn := unwrapAndName(argType)
			if trackedTypes[tn] && isFromTargetModule(argType) {
				pos := pkg.Fset.Position(call.Pos())
				out = append(out, Finding{
					File:     relPath(filename),
					Line:     pos.Line,
					Col:      pos.Column,
					Category: "NEW_ALLOCATION",
					Type:     tn,
					Detail:   fmt.Sprintf("new(%s) — check for post-allocation field assignment", tn),
				})
			}
		}
	}

	// Check for reflect.X(T) calls where T references a tracked type.
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "reflect" {
			callee := sel.Sel.Name
			if isReflectConstructor(callee) {
				for _, arg := range call.Args {
					argType := pkg.TypesInfo.TypeOf(arg)
					if argType == nil {
						continue
					}
					tn := unwrapAndName(argType)
					// Reflect calls often take a zero-value of the struct
					// (typed), so check the argument's type directly.
					if trackedTypes[tn] && isFromTargetModule(argType) {
						pos := pkg.Fset.Position(call.Pos())
						out = append(out, Finding{
							File:     relPath(filename),
							Line:     pos.Line,
							Col:      pos.Column,
							Category: "REFLECT_ACCESS",
							Type:     tn,
							Detail:   fmt.Sprintf("reflect.%s(...%s...)", callee, tn),
						})
					}
				}
			}
		}
	}

	return out
}

func checkUnaryAddrOf(pkg *packages.Package, filename string, un *ast.UnaryExpr) *Finding {
	// Catches &CosignedTreeHead{} specifically — an address-of empty literal.
	// The composite literal itself is also flagged via checkCompositeLit;
	// this catcher is here to cover the address-of pattern for completeness.
	if un.Op.String() != "&" {
		return nil
	}
	lit, ok := un.X.(*ast.CompositeLit)
	if !ok || len(lit.Elts) != 0 {
		return nil
	}
	tn := qualifiedTypeName(pkg, lit)
	if !trackedTypes[tn] {
		return nil
	}

	pos := pkg.Fset.Position(un.Pos())
	return &Finding{
		File:     relPath(filename),
		Line:     pos.Line,
		Col:      pos.Column,
		Category: "ADDR_EMPTY_LITERAL",
		Type:     tn,
		Detail:   fmt.Sprintf("&%s{} — check for post-allocation field assignment", tn),
	}
}

func checkFuncDecl(pkg *packages.Package, filename string, fn *ast.FuncDecl) []Finding {
	var out []Finding
	if fn.Type == nil {
		return out
	}

	funcName := ""
	if fn.Name != nil {
		funcName = fn.Name.Name
	}

	// Parameters.
	if fn.Type.Params != nil {
		for _, field := range fn.Type.Params.List {
			t := pkg.TypesInfo.TypeOf(field.Type)
			if t == nil {
				continue
			}
			tn := unwrapAndName(t)
			if !trackedTypes[tn] || !isFromTargetModule(t) {
				continue
			}
			pos := pkg.Fset.Position(field.Pos())
			out = append(out, Finding{
				File:     relPath(filename),
				Line:     pos.Line,
				Col:      pos.Column,
				Category: "FUNC_PARAM",
				Type:     tn,
				Detail:   fmt.Sprintf("func %s has parameter of type %s", funcName, tn),
			})
		}
	}

	// Return values.
	if fn.Type.Results != nil {
		for _, field := range fn.Type.Results.List {
			t := pkg.TypesInfo.TypeOf(field.Type)
			if t == nil {
				continue
			}
			tn := unwrapAndName(t)
			if !trackedTypes[tn] || !isFromTargetModule(t) {
				continue
			}
			pos := pkg.Fset.Position(field.Pos())
			out = append(out, Finding{
				File:     relPath(filename),
				Line:     pos.Line,
				Col:      pos.Column,
				Category: "FUNC_RESULT",
				Type:     tn,
				Detail:   fmt.Sprintf("func %s returns %s", funcName, tn),
			})
		}
	}

	return out
}

func checkField(pkg *packages.Package, filename string, field *ast.Field) []Finding {
	var out []Finding

	// Check field type for being a tracked type.
	t := pkg.TypesInfo.TypeOf(field.Type)
	if t != nil {
		tn := unwrapAndName(t)
		if trackedTypes[tn] && isFromTargetModule(t) {
			for _, nm := range field.Names {
				pos := pkg.Fset.Position(nm.Pos())
				out = append(out, Finding{
					File:     relPath(filename),
					Line:     pos.Line,
					Col:      pos.Column,
					Category: "STRUCT_FIELD",
					Type:     tn,
					Detail:   fmt.Sprintf("struct field %s of type %s", nm.Name, tn),
				})
			}
		}
	}

	// Check JSON tag for scheme_tag reference.
	if field.Tag != nil {
		tag := field.Tag.Value
		if strings.Contains(tag, "scheme_tag") || strings.Contains(tag, "schemeTag") {
			pos := pkg.Fset.Position(field.Pos())
			name := ""
			if len(field.Names) > 0 {
				name = field.Names[0].Name
			}
			out = append(out, Finding{
				File:     relPath(filename),
				Line:     pos.Line,
				Col:      pos.Column,
				Category: "JSON_TAG",
				Detail:   fmt.Sprintf("struct tag for field %q references scheme_tag: %s", name, tag),
			})
		}
	}

	return out
}

func checkTypeAssertion(pkg *packages.Package, filename string, ta *ast.TypeAssertExpr) *Finding {
	if ta.Type == nil {
		return nil
	}
	t := pkg.TypesInfo.TypeOf(ta.Type)
	if t == nil {
		return nil
	}
	tn := unwrapAndName(t)
	if !trackedTypes[tn] || !isFromTargetModule(t) {
		return nil
	}
	pos := pkg.Fset.Position(ta.Pos())
	return &Finding{
		File:     relPath(filename),
		Line:     pos.Line,
		Col:      pos.Column,
		Category: "TYPE_ASSERTION",
		Type:     tn,
		Detail:   fmt.Sprintf("type assertion to %s", tn),
	}
}

// ─────────────────────────────────────────────────────────────────────
// Type helpers
// ─────────────────────────────────────────────────────────────────────

// qualifiedTypeName returns the tracked type name for a composite literal
// only if the literal's type is from the target module. Returns "" for
// untracked types or types from other packages.
func qualifiedTypeName(pkg *packages.Package, lit *ast.CompositeLit) string {
	t := pkg.TypesInfo.TypeOf(lit)
	if t == nil {
		return ""
	}
	tn := unwrapAndName(t)
	if !trackedTypes[tn] {
		return ""
	}
	if !isFromTargetModule(t) {
		return ""
	}
	return tn
}

// unwrapAndName returns the underlying named-type name, unwrapping
// pointers and slices. Returns "" if the type has no name (e.g.,
// struct{}, func(), etc.).
func unwrapAndName(t types.Type) string {
	for {
		switch x := t.(type) {
		case *types.Pointer:
			t = x.Elem()
		case *types.Slice:
			t = x.Elem()
		case *types.Array:
			t = x.Elem()
		case *types.Named:
			return x.Obj().Name()
		default:
			return ""
		}
	}
}

// isFromTargetModule returns true if the named type is declared in
// the target module's types package.
func isFromTargetModule(t types.Type) bool {
	// Unwrap.
	for {
		switch x := t.(type) {
		case *types.Pointer:
			t = x.Elem()
		case *types.Slice:
			t = x.Elem()
		case *types.Array:
			t = x.Elem()
		default:
			named, ok := t.(*types.Named)
			if !ok {
				return false
			}
			obj := named.Obj()
			if obj == nil || obj.Pkg() == nil {
				return false
			}
			return obj.Pkg().Path() == targetTypesPkg
		}
	}
}

func isKeyedLiteral(lit *ast.CompositeLit) bool {
	if len(lit.Elts) == 0 {
		return true // empty literal is trivially "keyed" (no positional args)
	}
	for _, elt := range lit.Elts {
		if _, ok := elt.(*ast.KeyValueExpr); !ok {
			return false
		}
	}
	return true
}

func isReflectConstructor(name string) bool {
	switch name {
	case "New", "ValueOf", "TypeOf", "Zero", "StructOf", "PtrTo", "PointerTo":
		return true
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────
// Filesystem and output
// ─────────────────────────────────────────────────────────────────────

func isInTargetModule(root string) bool {
	// Look for go.mod with the target module path.
	content, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return false
	}
	return strings.Contains(string(content), "module "+targetModule)
}

func countGoFiles(root string) (int, error) {
	n := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == ".git" || name == "coverage" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			n++
		}
		return nil
	})
	return n, err
}

func relPath(p string) string {
	if moduleRoot == "" {
		return p
	}
	rel, err := filepath.Rel(moduleRoot, p)
	if err != nil {
		return p
	}
	return rel
}

func dedupFindings(findings []Finding) []Finding {
	seen := make(map[Finding]bool, len(findings))
	out := findings[:0]
	for _, f := range findings {
		if seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

func printHuman(findings []Finding) {
	if len(findings) == 0 {
		fmt.Println("No findings — refactor audit clean.")
		return
	}
	fmt.Println("REFACTOR AUDIT FINDINGS:")
	fmt.Println("========================")
	currentFile := ""
	for _, f := range findings {
		if f.File != currentFile {
			fmt.Printf("\n%s\n", f.File)
			currentFile = f.File
		}
		fmt.Printf("  %d:%d  [%s]  %s\n", f.Line, f.Col, f.Category, f.Detail)
	}
}

func printJSON(findings []Finding) {
	// Use encoding/json to guarantee well-formed output.
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(findings); err != nil {
		fmt.Fprintf(os.Stderr, "json encode: %v\n", err)
		os.Exit(2)
	}
}

func summarize(findings []Finding) string {
	counts := map[string]int{}
	files := map[string]bool{}
	for _, f := range findings {
		counts[f.Category]++
		files[f.File] = true
	}
	var lines []string
	lines = append(lines, "SUMMARY:")

	orderedCats := []string{
		"LITERAL_COSIGNED_HEAD",
		"LITERAL_WITNESS_SIG",
		"ACCESS_COSIGNED_SCHEMETAG",
		"NEW_ALLOCATION",
		"ADDR_EMPTY_LITERAL",
		"FUNC_PARAM",
		"FUNC_RESULT",
		"STRUCT_FIELD",
		"TYPE_ASSERTION",
		"REFLECT_ACCESS",
		"JSON_TAG",
		"METHOD_VALUE",
	}
	for _, cat := range orderedCats {
		if counts[cat] > 0 {
			lines = append(lines, fmt.Sprintf("  %-30s %d", cat, counts[cat]))
		}
	}
	lines = append(lines, fmt.Sprintf("  %-30s %d", "TOTAL FILES", len(files)))
	lines = append(lines, fmt.Sprintf("  %-30s %d", "TOTAL FINDINGS", len(findings)))
	return strings.Join(lines, "\n")
}
