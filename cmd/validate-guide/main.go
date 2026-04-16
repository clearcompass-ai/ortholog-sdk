// Command validate-guide inspects the Ortholog SDK source tree and prints
// evidence for or against documentation claims in the SDK guide.
//
// Run from the SDK repo root:
//
//	go run ./cmd/validate-guide
//
// Output is grouped by claim. Each section prints:
//   - The question being validated
//   - The evidence found (or "NONE FOUND")
//   - File:line citations for every finding
//
// The script does not interpret findings — it surfaces facts. Whether
// the guide is correct relative to those facts is for the reader to
// decide.
//
// What this tool can do (with AST):
//   - Enumerate exported identifiers (constants, types, functions, interfaces)
//   - Find constant values for typed enums (PathResult, AuthorityPath, etc.)
//   - Locate every declaration site of a name across the tree
//   - Inspect function bodies for specific calls or literal values
//   - List interface method sets
//
// What this tool cannot do:
//   - Read string-literal documentation accurately (comments are AST-visible
//     but their meaning is not — we extract them but don't interpret them)
//   - Determine runtime behavior (e.g., what value a field has after init)
//   - Verify cross-language wire format claims
//
// The script intentionally fails closed: if a file fails to parse, it prints
// the error and continues with other files rather than silently producing
// incomplete results.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────
// Entry point and structure
// ─────────────────────────────────────────────────────────────────────

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}

	abs, err := filepath.Abs(root)
	if err != nil {
		fatalf("resolve root: %v", err)
	}

	fmt.Printf("# Ortholog SDK Guide Validation Report\n\n")
	fmt.Printf("Root: %s\n\n", abs)

	pkgs := loadAllPackages(abs)
	fmt.Printf("Parsed %d Go files across %d packages.\n\n", countFiles(pkgs), len(pkgs))

	separator()

	// ─── Tier 2 claims ──────────────────────────────────────────────
	claim_2_1_PathResultConstants(pkgs)
	claim_2_2_AuthorityPathConstants(pkgs)
	claim_2_6_DeltaWindowDefault(pkgs)
	claim_2_7_Argon2idSaltUsage(pkgs)
	claim_2_9_OriginConstants(pkgs)
	claim_2_10_EntryFetcherDeclarations(pkgs)

	// ─── General-purpose audits ─────────────────────────────────────
	auditExportedIdentifiers(pkgs)
	auditInterfaceMethodSets(pkgs)
}

// ─────────────────────────────────────────────────────────────────────
// Package loading
// ─────────────────────────────────────────────────────────────────────

type loadedPkg struct {
	importPath string // e.g. "builder", "core/smt"
	files      map[string]*ast.File
	fset       *token.FileSet
}

// loadAllPackages walks the SDK tree, parses every .go file, and groups
// by directory. Test files are included — many tests reference symbols
// the guide describes.
func loadAllPackages(root string) []*loadedPkg {
	pkgsByDir := map[string]*loadedPkg{}
	fset := token.NewFileSet()

	skip := map[string]bool{
		".git": true, ".wave2-3-backup-20260416-130031": true,
		"node_modules": true,
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if skip[d.Name()] || strings.HasPrefix(d.Name(), ".wave") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}

		dir := filepath.Dir(path)
		rel, _ := filepath.Rel(root, dir)
		if rel == "." {
			rel = "(root)"
		}

		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: parse %s: %v\n", path, err)
			return nil
		}

		pkg, ok := pkgsByDir[rel]
		if !ok {
			pkg = &loadedPkg{importPath: rel, files: map[string]*ast.File{}, fset: fset}
			pkgsByDir[rel] = pkg
		}
		pkg.files[path] = file
		return nil
	})
	if err != nil {
		fatalf("walk: %v", err)
	}

	out := make([]*loadedPkg, 0, len(pkgsByDir))
	for _, p := range pkgsByDir {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].importPath < out[j].importPath })
	return out
}

func countFiles(pkgs []*loadedPkg) int {
	n := 0
	for _, p := range pkgs {
		n += len(p.files)
	}
	return n
}

// ─────────────────────────────────────────────────────────────────────
// Claim 2.1 — PathResult constants
// ─────────────────────────────────────────────────────────────────────

func claim_2_1_PathResultConstants(pkgs []*loadedPkg) {
	header("Claim 2.1: How many PathResult constants exist?")
	explain(`The guide says "five state-affecting operations" but section 9.2 lists
seven PathResult bucket types. We need to count the actual constants.`)

	consts := findConstantsOfType(pkgs, "PathResult")
	if len(consts) == 0 {
		fmt.Println("NONE FOUND.")
		separator()
		return
	}

	fmt.Printf("Found %d PathResult constants:\n", len(consts))
	for _, c := range consts {
		fmt.Printf("  %-30s  (%s)\n", c.name, c.location)
		if c.docComment != "" {
			fmt.Printf("    └─ %s\n", firstLine(c.docComment))
		}
	}
	fmt.Println()
	fmt.Printf("ANSWER: %d constants. Guide claim of 'seven' is %s.\n",
		len(consts), verdict(len(consts) == 7))
	separator()
}

// ─────────────────────────────────────────────────────────────────────
// Claim 2.2 — AuthorityPath constants
// ─────────────────────────────────────────────────────────────────────

func claim_2_2_AuthorityPathConstants(pkgs []*loadedPkg) {
	header("Claim 2.2: What AuthorityPath constant values exist?")
	explain(`The guide section 9.2 references AuthoritySameSigner, AuthorityDelegation,
and AuthorityScopeAuthority but section 5.2 doesn't enumerate them where
the AuthorityPath field is first introduced.`)

	// AuthorityPath might be a typed enum or just a set of named constants.
	// Look for both.
	consts := findConstantsOfType(pkgs, "AuthorityPath")
	if len(consts) == 0 {
		// Fall back to name-pattern search
		consts = findConstantsByPrefix(pkgs, "Authority", []string{"SameSigner", "Delegation", "ScopeAuthority"})
	}

	if len(consts) == 0 {
		fmt.Println("NONE FOUND under typed enum search or name pattern.")
		fmt.Println("ACTION: search source for these strings manually.")
		separator()
		return
	}

	fmt.Printf("Found %d candidate constants:\n", len(consts))
	for _, c := range consts {
		fmt.Printf("  %-35s  (%s)\n", c.name, c.location)
	}
	fmt.Println()
	fmt.Println("ANSWER: above constants are what the guide should enumerate in section 5.2.")
	separator()
}

// ─────────────────────────────────────────────────────────────────────
// Claim 2.6 — Δ-window default size
// ─────────────────────────────────────────────────────────────────────

func claim_2_6_DeltaWindowDefault(pkgs []*loadedPkg) {
	header("Claim 2.6: What is the default Δ-window size?")
	explain(`The guide section 10.1 claims "N defaults to 10". We need to find:
(a) what NewDeltaWindowBuffer accepts as its size argument
(b) what default is used when ProcessBatch receives a nil buffer
(c) whether SchemaResolution.DeltaWindowSize defaults to 10 or something else`)

	// Find NewDeltaWindowBuffer signature
	fn := findFunction(pkgs, "NewDeltaWindowBuffer")
	if fn != nil {
		fmt.Printf("NewDeltaWindowBuffer signature at %s:\n", fn.location)
		fmt.Printf("  %s\n", fn.signature)
	}

	// Look for nil-buffer handling in ProcessBatch — print the snippet
	snippets := findFunctionBodySnippets(pkgs, "ProcessBatch", "NewDeltaWindowBuffer(")
	if len(snippets) > 0 {
		fmt.Println("\nProcessBatch nil-buffer handling:")
		for _, s := range snippets {
			fmt.Printf("  %s\n    %s\n", s.location, s.text)
		}
	}

	// Find SchemaResolution.DeltaWindowSize default doc
	field := findStructField(pkgs, "SchemaResolution", "DeltaWindowSize")
	if field != nil {
		fmt.Printf("\nSchemaResolution.DeltaWindowSize at %s:\n", field.location)
		if field.docComment != "" {
			for _, line := range strings.Split(strings.TrimSpace(field.docComment), "\n") {
				fmt.Printf("  %s\n", line)
			}
		}
	}

	fmt.Println("\nANSWER: compare the literal integer in 'NewDeltaWindowBuffer(N)' calls")
	fmt.Println("inside ProcessBatch against the guide's claim of 10.")
	separator()
}

// ─────────────────────────────────────────────────────────────────────
// Claim 2.7 — Argon2id salt usage
// ─────────────────────────────────────────────────────────────────────

func claim_2_7_Argon2idSaltUsage(pkgs []*loadedPkg) {
	header("Claim 2.7: Is argon2Salt only used inside the HashArgon2id branch?")
	explain(`The guide section 16.2 implies the salt applies to both algorithms.
We need to verify the salt is referenced ONLY in code paths gated by
HashArgon2id. Otherwise the guide's qualification "Argon2id only" is wrong.`)

	uses := findIdentifierReferences(pkgs, "argon2Salt")
	if len(uses) == 0 {
		fmt.Println("argon2Salt not found. Guide may reference a renamed symbol.")
		separator()
		return
	}

	fmt.Printf("Found %d references to argon2Salt:\n", len(uses))
	for _, u := range uses {
		fmt.Printf("  %s\n", u.location)
		if u.containingFunc != "" {
			fmt.Printf("    └─ inside function: %s\n", u.containingFunc)
		}
		if u.surroundingCase != "" {
			fmt.Printf("    └─ inside case: %s\n", u.surroundingCase)
		}
	}

	fmt.Println("\nANSWER: every use should be inside a 'case HashArgon2id:' branch.")
	fmt.Println("If any use is outside such a branch, the guide's qualification is incorrect")
	fmt.Println("and the salt is being applied more broadly than documented.")
	separator()
}

// ─────────────────────────────────────────────────────────────────────
// Claim 2.9 — Origin* constants
// ─────────────────────────────────────────────────────────────────────

func claim_2_9_OriginConstants(pkgs []*loadedPkg) {
	header("Claim 2.9: What Origin* states exist in OriginEvaluation?")
	explain(`The guide section 23.1 lists five Origin states:
  OriginOriginal, OriginAmended, OriginRevoked, OriginSucceeded, OriginPending
We need to verify the actual constant set, including whether
OriginNotFound exists (which the guide doesn't mention).`)

	// Look for any constants/types named Origin* in verifier package
	all := findConstantsByPrefix(pkgs, "Origin", nil)
	if len(all) == 0 {
		fmt.Println("NONE FOUND.")
		separator()
		return
	}

	fmt.Printf("Found %d Origin* constants:\n", len(all))
	for _, c := range all {
		fmt.Printf("  %-30s  (%s)\n", c.name, c.location)
	}
	fmt.Println()
	expected := map[string]bool{
		"OriginOriginal":  false,
		"OriginAmended":   false,
		"OriginRevoked":   false,
		"OriginSucceeded": false,
		"OriginPending":   false,
	}
	for _, c := range all {
		if _, ok := expected[c.name]; ok {
			expected[c.name] = true
		}
	}
	fmt.Println("Guide-claimed states present?")
	for name, found := range expected {
		fmt.Printf("  %-30s %s\n", name, presence(found))
	}

	// Anything else not in the expected set is a guide gap
	fmt.Println("\nUndocumented states (in code but not in guide):")
	gap := false
	for _, c := range all {
		if _, expected := expected[c.name]; !expected {
			fmt.Printf("  %s  (%s)\n", c.name, c.location)
			gap = true
		}
	}
	if !gap {
		fmt.Println("  (none — all constants are documented)")
	}
	separator()
}

// ─────────────────────────────────────────────────────────────────────
// Claim 2.10 — EntryFetcher declarations
// ─────────────────────────────────────────────────────────────────────

func claim_2_10_EntryFetcherDeclarations(pkgs []*loadedPkg) {
	header("Claim 2.10: How many packages declare 'type EntryFetcher interface'?")
	explain(`The guide section 27.1 originally said "three times". We previously
found two via grep (builder, verifier). Confirm via AST and check
whether the two definitions are structurally identical.`)

	type ifaceDecl struct {
		pkg      string
		location string
		methods  []string // "MethodName(params) returns"
	}

	var found []ifaceDecl
	for _, pkg := range pkgs {
		for _, file := range pkg.files {
			ast.Inspect(file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok || ts.Name.Name != "EntryFetcher" {
					return true
				}
				iface, ok := ts.Type.(*ast.InterfaceType)
				if !ok {
					return true
				}
				decl := ifaceDecl{
					pkg:      pkg.importPath,
					location: posString(pkg.fset, ts.Pos()),
				}
				for _, method := range iface.Methods.List {
					decl.methods = append(decl.methods, methodSig(method))
				}
				found = append(found, decl)
				return false
			})
		}
	}

	fmt.Printf("Found %d declarations of EntryFetcher:\n", len(found))
	for _, d := range found {
		fmt.Printf("  package %s at %s\n", d.pkg, d.location)
		for _, m := range d.methods {
			fmt.Printf("    %s\n", m)
		}
	}

	if len(found) >= 2 {
		// Compare method signatures across declarations
		first := strings.Join(found[0].methods, "|")
		identical := true
		for _, d := range found[1:] {
			if strings.Join(d.methods, "|") != first {
				identical = false
				break
			}
		}
		fmt.Printf("\nAll %d declarations structurally identical: %s\n",
			len(found), boolStr(identical))
	}
	separator()
}

// ─────────────────────────────────────────────────────────────────────
// Audit: every exported identifier
// ─────────────────────────────────────────────────────────────────────

func auditExportedIdentifiers(pkgs []*loadedPkg) {
	header("Audit: every exported identifier per package")
	explain(`Reference inventory. Useful to cross-check guide claims like
"the SDK exports X" or "X is unexported". Skips test files.`)

	for _, pkg := range pkgs {
		var consts, types_, funcs, vars []string
		for path, file := range pkg.files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			for _, decl := range file.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						switch s := spec.(type) {
						case *ast.TypeSpec:
							if s.Name.IsExported() {
								types_ = append(types_, s.Name.Name)
							}
						case *ast.ValueSpec:
							for _, name := range s.Names {
								if !name.IsExported() {
									continue
								}
								if d.Tok == token.CONST {
									consts = append(consts, name.Name)
								} else {
									vars = append(vars, name.Name)
								}
							}
						}
					}
				case *ast.FuncDecl:
					if d.Name.IsExported() && d.Recv == nil {
						funcs = append(funcs, d.Name.Name)
					}
				}
			}
		}

		if len(consts)+len(types_)+len(funcs)+len(vars) == 0 {
			continue
		}

		sort.Strings(consts)
		sort.Strings(types_)
		sort.Strings(funcs)
		sort.Strings(vars)

		fmt.Printf("\n## %s\n", pkg.importPath)
		printList("constants", consts)
		printList("types    ", types_)
		printList("functions", funcs)
		printList("variables", vars)
	}
	separator()
}

// ─────────────────────────────────────────────────────────────────────
// Audit: interface method sets
// ─────────────────────────────────────────────────────────────────────

func auditInterfaceMethodSets(pkgs []*loadedPkg) {
	header("Audit: every exported interface and its method set")
	explain(`Useful for verifying claims about structural typing — when the
guide says "interface X is satisfied by type Y", you can check Y's
methods against X's method set.`)

	for _, pkg := range pkgs {
		printed := false
		for path, file := range pkg.files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok || !ts.Name.IsExported() {
					return true
				}
				iface, ok := ts.Type.(*ast.InterfaceType)
				if !ok {
					return true
				}
				if !printed {
					fmt.Printf("\n## %s\n", pkg.importPath)
					printed = true
				}
				fmt.Printf("\n  %s (%s)\n", ts.Name.Name, posString(pkg.fset, ts.Pos()))
				for _, method := range iface.Methods.List {
					fmt.Printf("    %s\n", methodSig(method))
				}
				return false
			})
		}
	}
	separator()
}

// ─────────────────────────────────────────────────────────────────────
// AST helpers
// ─────────────────────────────────────────────────────────────────────

type constInfo struct {
	name       string
	location   string
	docComment string
}

// findConstantsOfType returns every const declared with the given typed enum.
// Handles both "const X TypeName = 1" and the iota pattern:
//
//	const (
//	    First TypeName = iota
//	    Second
//	    ...
//	)
func findConstantsOfType(pkgs []*loadedPkg, typeName string) []constInfo {
	var out []constInfo
	for _, pkg := range pkgs {
		for _, file := range pkg.files {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}

				// Track the most recent type seen — iota carries it forward
				var lastType string
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					if vs.Type != nil {
						if id, ok := vs.Type.(*ast.Ident); ok {
							lastType = id.Name
						}
					}
					if lastType != typeName {
						continue
					}
					for _, name := range vs.Names {
						doc := ""
						if vs.Doc != nil {
							doc = vs.Doc.Text()
						}
						out = append(out, constInfo{
							name:       name.Name,
							location:   posString(pkg.fset, name.Pos()),
							docComment: doc,
						})
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// findConstantsByPrefix returns constants whose names start with prefix.
// If suffixes is non-nil, only returns constants with one of those suffixes.
func findConstantsByPrefix(pkgs []*loadedPkg, prefix string, suffixes []string) []constInfo {
	var out []constInfo
	for _, pkg := range pkgs {
		for _, file := range pkg.files {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					for _, name := range vs.Names {
						if !strings.HasPrefix(name.Name, prefix) {
							continue
						}
						if len(suffixes) > 0 {
							ok := false
							for _, s := range suffixes {
								if strings.HasSuffix(name.Name, s) {
									ok = true
									break
								}
							}
							if !ok {
								continue
							}
						}
						out = append(out, constInfo{
							name:     name.Name,
							location: posString(pkg.fset, name.Pos()),
						})
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

type funcInfo struct {
	location  string
	signature string
}

func findFunction(pkgs []*loadedPkg, name string) *funcInfo {
	for _, pkg := range pkgs {
		for _, file := range pkg.files {
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Recv != nil || fd.Name.Name != name {
					continue
				}
				return &funcInfo{
					location:  posString(pkg.fset, fd.Pos()),
					signature: renderFuncSignature(fd),
				}
			}
		}
	}
	return nil
}

type fieldInfo struct {
	location   string
	docComment string
}

func findStructField(pkgs []*loadedPkg, structName, fieldName string) *fieldInfo {
	for _, pkg := range pkgs {
		for _, file := range pkg.files {
			var found *fieldInfo
			ast.Inspect(file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok || ts.Name.Name != structName {
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					return true
				}
				for _, field := range st.Fields.List {
					for _, name := range field.Names {
						if name.Name != fieldName {
							continue
						}
						doc := ""
						if field.Doc != nil {
							doc = field.Doc.Text()
						}
						found = &fieldInfo{
							location:   posString(pkg.fset, name.Pos()),
							docComment: doc,
						}
						return false
					}
				}
				return false
			})
			if found != nil {
				return found
			}
		}
	}
	return nil
}

type bodySnippet struct {
	location string
	text     string
}

// findFunctionBodySnippets returns lines from funcName's body that contain searchText.
func findFunctionBodySnippets(pkgs []*loadedPkg, funcName, searchText string) []bodySnippet {
	var out []bodySnippet
	for _, pkg := range pkgs {
		for path, file := range pkg.files {
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Name.Name != funcName || fd.Body == nil {
					continue
				}
				// Read source bytes for the body
				src, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				start := pkg.fset.Position(fd.Body.Pos()).Offset
				end := pkg.fset.Position(fd.Body.End()).Offset
				if end > len(src) {
					end = len(src)
				}
				body := string(src[start:end])
				// Find lines containing searchText
				bodyStart := pkg.fset.Position(fd.Body.Pos()).Line
				for lineNum, line := range strings.Split(body, "\n") {
					if strings.Contains(line, searchText) {
						out = append(out, bodySnippet{
							location: fmt.Sprintf("%s:%d", path, bodyStart+lineNum),
							text:     strings.TrimSpace(line),
						})
					}
				}
			}
		}
	}
	return out
}

type identUse struct {
	location        string
	containingFunc  string
	surroundingCase string
}

// findIdentifierReferences finds every reference to identName, recording
// the enclosing function and (if inside a switch) the case branch.
func findIdentifierReferences(pkgs []*loadedPkg, identName string) []identUse {
	var out []identUse
	for _, pkg := range pkgs {
		for _, file := range pkg.files {
			// Build a stack of contexts as we walk
			type ctx struct {
				funcName string
				caseExpr string
			}
			stack := []ctx{{}}

			ast.Inspect(file, func(n ast.Node) bool {
				if n == nil {
					if len(stack) > 1 {
						stack = stack[:len(stack)-1]
					}
					return true
				}
				switch node := n.(type) {
				case *ast.FuncDecl:
					top := stack[len(stack)-1]
					top.funcName = node.Name.Name
					stack = append(stack, top)
				case *ast.CaseClause:
					top := stack[len(stack)-1]
					var labels []string
					for _, lit := range node.List {
						labels = append(labels, exprToString(lit))
					}
					top.caseExpr = strings.Join(labels, ", ")
					stack = append(stack, top)
				case *ast.Ident:
					if node.Name == identName && node.Obj == nil {
						top := stack[len(stack)-1]
						out = append(out, identUse{
							location:        posString(pkg.fset, node.Pos()),
							containingFunc:  top.funcName,
							surroundingCase: top.caseExpr,
						})
					}
				}
				return true
			})
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────
// Rendering helpers
// ─────────────────────────────────────────────────────────────────────

func methodSig(field *ast.Field) string {
	if len(field.Names) == 0 {
		return "<embedded>"
	}
	name := field.Names[0].Name
	ft, ok := field.Type.(*ast.FuncType)
	if !ok {
		return name
	}
	return fmt.Sprintf("%s%s", name, renderFuncType(ft))
}

func renderFuncSignature(fd *ast.FuncDecl) string {
	return fmt.Sprintf("func %s%s", fd.Name.Name, renderFuncType(fd.Type))
}

func renderFuncType(ft *ast.FuncType) string {
	var sb strings.Builder
	sb.WriteString("(")
	if ft.Params != nil {
		first := true
		for _, p := range ft.Params.List {
			for _, name := range p.Names {
				if !first {
					sb.WriteString(", ")
				}
				first = false
				sb.WriteString(name.Name + " " + exprToString(p.Type))
			}
			if len(p.Names) == 0 {
				if !first {
					sb.WriteString(", ")
				}
				first = false
				sb.WriteString(exprToString(p.Type))
			}
		}
	}
	sb.WriteString(")")
	if ft.Results != nil && len(ft.Results.List) > 0 {
		sb.WriteString(" ")
		if len(ft.Results.List) > 1 {
			sb.WriteString("(")
		}
		for i, r := range ft.Results.List {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(exprToString(r.Type))
		}
		if len(ft.Results.List) > 1 {
			sb.WriteString(")")
		}
	}
	return sb.String()
}

func exprToString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprToString(x.X) + "." + x.Sel.Name
	case *ast.StarExpr:
		return "*" + exprToString(x.X)
	case *ast.ArrayType:
		if x.Len != nil {
			return "[" + exprToString(x.Len) + "]" + exprToString(x.Elt)
		}
		return "[]" + exprToString(x.Elt)
	case *ast.MapType:
		return "map[" + exprToString(x.Key) + "]" + exprToString(x.Value)
	case *ast.BasicLit:
		return x.Value
	case *ast.InterfaceType:
		return "interface{...}"
	case *ast.FuncType:
		return "func" + renderFuncType(x)
	case *ast.Ellipsis:
		return "..." + exprToString(x.Elt)
	case *ast.ChanType:
		return "chan " + exprToString(x.Value)
	}
	return "?"
}

func posString(fset *token.FileSet, pos token.Pos) string {
	p := fset.Position(pos)
	rel := p.Filename
	if abs, err := filepath.Abs(p.Filename); err == nil {
		if cwd, err := os.Getwd(); err == nil {
			if r, err := filepath.Rel(cwd, abs); err == nil {
				rel = r
			}
		}
	}
	return fmt.Sprintf("%s:%d", rel, p.Line)
}

// ─────────────────────────────────────────────────────────────────────
// Output formatting
// ─────────────────────────────────────────────────────────────────────

func header(s string) {
	fmt.Println()
	fmt.Println(strings.Repeat("═", 70))
	fmt.Println(s)
	fmt.Println(strings.Repeat("═", 70))
}

func separator() {
	fmt.Println()
	fmt.Println(strings.Repeat("─", 70))
	fmt.Println()
}

func explain(s string) {
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		fmt.Printf("  %s\n", line)
	}
	fmt.Println()
}

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func verdict(b bool) string {
	if b {
		return "MATCHES"
	}
	return "DOES NOT MATCH"
}

func presence(b bool) string {
	if b {
		return "✓ present"
	}
	return "✗ MISSING"
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func printList(label string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Printf("  %s (%d): %s\n", label, len(items), strings.Join(items, ", "))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}

// Unused import suppressor — strconv is reserved for future numeric checks
var _ = strconv.Itoa
