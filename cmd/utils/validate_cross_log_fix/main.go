// Package main provides comprehensive AST validation of the ORTHO-BUG-001 fix.
// See original header for full docs.
//
// CHANGES from v1:
//   - Suite 1 B1: counts calls to envelope.EntryLeafHash AND envelope.EntryLeafHashBytes.
//     Either form is valid; cross_log typically uses the Bytes variant since
//     it already has CanonicalBytes from EntryWithMetadata.
//   - Suite 2: finds all functions named EntryLeafHash* (both the *Entry and
//     []byte variants can coexist in the same package). Reports both.
//   - Suite 2 E2: accepts func(*Entry) [32]byte OR func([]byte) [32]byte.
//     At least one signature must be present; both is fine.
//   - Suite 2 E4: accepts a 0x00 literal OR a reference to the
//     RFC6962LeafPrefix named constant OR an rfc6962 package import.

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

type check struct {
	id       string
	name     string
	passed   bool
	detail   string
	critical bool
}

type suite struct {
	title  string
	file   string
	checks []check
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: validate_ortho_bug_001 <sdk-root>")
		os.Exit(2)
	}
	sdkRoot := os.Args[1]

	fi, err := os.Stat(sdkRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: cannot stat %q: %v\n", sdkRoot, err)
		os.Exit(2)
	}
	if !fi.IsDir() {
		fmt.Fprintf(os.Stderr, "fatal: %q is not a directory\n", sdkRoot)
		os.Exit(2)
	}

	suites := []suite{
		validateCrossLog(sdkRoot),
		validateEnvelope(sdkRoot),
		validateTests(sdkRoot),
	}

	printReport(sdkRoot, suites)
}

func printReport(sdkRoot string, suites []suite) {
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println(" ORTHO-BUG-001 Fix Validation (v2)")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Printf(" SDK root: %s\n\n", sdkRoot)

	total, passed, criticalFailures := 0, 0, 0
	for _, s := range suites {
		fmt.Printf("── %s ──\n", s.title)
		if s.file != "" {
			fmt.Printf("   file: %s\n", s.file)
		}
		if len(s.checks) == 0 {
			fmt.Println("   (no checks)")
			fmt.Println()
			continue
		}
		for _, c := range s.checks {
			printCheck(c)
			total++
			if c.passed {
				passed++
			} else if c.critical {
				criticalFailures++
			}
		}
		fmt.Println()
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Printf(" Summary: %d/%d checks passed\n", passed, total)
	if criticalFailures == 0 {
		fmt.Println(" ✓ ORTHO-BUG-001 fix appears COMPLETE.")
		fmt.Println("═══════════════════════════════════════════════════════")
		os.Exit(0)
	}
	fmt.Printf(" ✗ ORTHO-BUG-001 fix is INCOMPLETE (%d critical failures).\n", criticalFailures)
	fmt.Println("═══════════════════════════════════════════════════════")
	os.Exit(1)
}

func printCheck(c check) {
	var status string
	switch {
	case c.passed:
		status = "✓ PASS"
	case !c.critical:
		status = "∼ INFO"
	default:
		status = "✗ FAIL"
	}
	fmt.Printf("  [%s] %s — %s\n         %s\n", c.id, status, c.name, c.detail)
}

// ═══ Suite 1: verifier/cross_log.go ═══════════════════════════════

func validateCrossLog(sdkRoot string) suite {
	path := filepath.Join(sdkRoot, "verifier", "cross_log.go")
	s := suite{title: "Suite 1 — verifier/cross_log.go (primary fix)", file: path}

	if _, err := os.Stat(path); err != nil {
		s.checks = append(s.checks, check{id: "S1", name: "cross_log.go exists", critical: true, detail: err.Error()})
		return s
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		s.checks = append(s.checks, check{id: "S1", name: "parses as Go", critical: true, detail: err.Error()})
		return s
	}

	var buildFn, verifyFn *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil {
			continue
		}
		switch fn.Name.Name {
		case "BuildCrossLogProof":
			buildFn = fn
		case "VerifyCrossLogProof":
			verifyFn = fn
		}
	}
	if buildFn == nil || verifyFn == nil {
		s.checks = append(s.checks, check{id: "S1", name: "Build+Verify functions exist", critical: true,
			detail: fmt.Sprintf("buildFn=%v verifyFn=%v", buildFn != nil, verifyFn != nil)})
		return s
	}

	// B1 (updated): count calls to EntryLeafHash OR EntryLeafHashBytes
	nLeaf := countQualifiedCalls(buildFn.Body, "envelope", "EntryLeafHash")
	nLeafBytes := countQualifiedCalls(buildFn.Body, "envelope", "EntryLeafHashBytes")
	total := nLeaf + nLeafBytes
	s.checks = append(s.checks, check{
		id: "B1", name: "BuildCrossLogProof uses envelope.EntryLeafHash(Bytes) (RFC 6962)",
		passed: total >= 2, critical: true,
		detail: fmt.Sprintf("EntryLeafHash=%d EntryLeafHashBytes=%d total=%d (expected ≥2)", nLeaf, nLeafBytes, total),
	})

	n := countQualifiedCalls(buildFn.Body, "sha256", "Sum256")
	s.checks = append(s.checks, check{
		id: "B2", name: "BuildCrossLogProof does NOT use raw sha256.Sum256 for entry hashes",
		passed: n == 0, critical: true,
		detail: fmt.Sprintf("found %d sha256.Sum256 call(s), expected 0", n),
	})

	hasFetcher := false
	var fetcherParam string
	for _, p := range verifyFn.Type.Params.List {
		if strings.Contains(exprString(p.Type), "Fetcher") {
			hasFetcher = true
			if len(p.Names) > 0 {
				fetcherParam = p.Names[0].Name
			}
			break
		}
	}
	s.checks = append(s.checks, check{
		id: "V1", name: "VerifyCrossLogProof signature includes a Fetcher parameter",
		passed: hasFetcher, critical: true,
		detail: fmt.Sprintf("hasFetcher=%v name=%q", hasFetcher, fetcherParam),
	})

	f := hasChainedSelector(verifyFn.Body, "SourceInclusion", "LeafHash")
	s.checks = append(s.checks, check{id: "V2", name: "Body accesses SourceInclusion.LeafHash",
		passed: f, critical: true, detail: fmt.Sprintf("found=%v", f)})

	f = hasChainedSelector(verifyFn.Body, "LocalInclusion", "LeafHash")
	s.checks = append(s.checks, check{id: "V3", name: "Body accesses LocalInclusion.LeafHash",
		passed: f, critical: true, detail: fmt.Sprintf("found=%v", f)})

	f = hasBindingComparison(verifyFn.Body, "SourceInclusion", "LeafHash", "SourceEntryHash")
	s.checks = append(s.checks, check{id: "V4", name: "Compares SourceInclusion.LeafHash vs SourceEntryHash",
		passed: f, critical: true, detail: fmt.Sprintf("found=%v", f)})

	f = hasBindingComparison(verifyFn.Body, "LocalInclusion", "LeafHash", "AnchorEntryHash")
	s.checks = append(s.checks, check{id: "V5", name: "Compares LocalInclusion.LeafHash vs AnchorEntryHash",
		passed: f, critical: true, detail: fmt.Sprintf("found=%v", f)})

	hasDP := hasSelectorWithName(verifyFn.Body, "DomainPayload")
	hasCB := hasSelectorWithName(verifyFn.Body, "CanonicalBytes")
	s.checks = append(s.checks, check{
		id: "V6", name: "Inspects anchor entry content (DomainPayload or CanonicalBytes)",
		passed: hasDP || hasCB, critical: true,
		detail: fmt.Sprintf("DomainPayload=%v CanonicalBytes=%v", hasDP, hasCB),
	})

	refs := countIdentifierUse(verifyFn.Body, "AnchorTreeHeadRef")
	s.checks = append(s.checks, check{
		id: "V7", name: "AnchorTreeHeadRef referenced ≥ 2 times (content binding)",
		passed: refs >= 2, critical: true,
		detail: fmt.Sprintf("found %d references, expected ≥2", refs),
	})

	fetchCalled := false
	if fetcherParam != "" {
		fetchCalled = hasMethodCallOn(verifyFn.Body, fetcherParam, "Fetch")
	}
	s.checks = append(s.checks, check{
		id: "V8", name: "fetcher.Fetch called at top level (informational)",
		passed: !hasFetcher || fetchCalled, critical: false,
		detail: fmt.Sprintf("fetchCalled=%v", fetchCalled),
	})

	return s
}

// ═══ Suite 2: core/envelope ═══════════════════════════════════════

type leafHashFn struct {
	name       string
	file       string
	line       int
	paramType  string
	resultType string
	usesSHA256 bool
	usesZero   bool // 0x00 literal OR RFC6962LeafPrefix identifier
}

func validateEnvelope(sdkRoot string) suite {
	envelopeDir := filepath.Join(sdkRoot, "core", "envelope")
	s := suite{title: "Suite 2 — core/envelope/ (EntryLeafHash functions, RFC 6962)"}

	if _, err := os.Stat(envelopeDir); err != nil {
		s.checks = append(s.checks, check{id: "S2", name: "core/envelope exists", critical: true, detail: err.Error()})
		return s
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, envelopeDir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		s.checks = append(s.checks, check{id: "S2", name: "core/envelope parses", critical: true, detail: err.Error()})
		return s
	}

	importsRFC6962 := false
	var fns []leafHashFn
	for _, pkg := range pkgs {
		for fname, f := range pkg.Files {
			for _, imp := range f.Imports {
				if strings.Contains(imp.Path.Value, "rfc6962") {
					importsRFC6962 = true
				}
			}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Recv != nil {
					continue
				}
				if !strings.HasPrefix(fd.Name.Name, "EntryLeafHash") {
					continue
				}
				lh := leafHashFn{
					name: fd.Name.Name,
					file: fname,
					line: fset.Position(fd.Pos()).Line,
				}
				if fd.Type.Params != nil && len(fd.Type.Params.List) == 1 {
					lh.paramType = exprString(fd.Type.Params.List[0].Type)
				}
				if fd.Type.Results != nil && len(fd.Type.Results.List) == 1 {
					lh.resultType = exprString(fd.Type.Results.List[0].Type)
				}
				lh.usesSHA256 = countQualifiedCalls(fd.Body, "sha256", "Sum256") > 0 ||
					countQualifiedCalls(fd.Body, "sha256", "New") > 0
				// Zero detection: either a literal 0 in a []byte{...}, or a reference
				// to the RFC6962LeafPrefix constant.
				lh.usesZero = hasIntLiteralZero(fd.Body) ||
					countIdentifierUse(fd.Body, "RFC6962LeafPrefix") > 0
				fns = append(fns, lh)
			}
		}
	}

	if len(fns) == 0 {
		s.checks = append(s.checks, check{
			id: "E1", name: "EntryLeafHash* function(s) exist",
			passed: false, critical: true,
			detail: "no functions starting with EntryLeafHash found under core/envelope/",
		})
		return s
	}

	// Pick the most informative file for the suite header
	s.file = fns[0].file

	names := make([]string, 0, len(fns))
	for _, fn := range fns {
		names = append(names, fmt.Sprintf("%s(%s)→%s @%s:%d", fn.name, fn.paramType, fn.resultType, filepath.Base(fn.file), fn.line))
	}
	s.checks = append(s.checks, check{
		id: "E1", name: "EntryLeafHash* function(s) exist",
		passed: true, critical: true,
		detail: fmt.Sprintf("found %d: %s", len(fns), strings.Join(names, "; ")),
	})

	// E2: at least one function has func(*Entry)[32]byte OR func([]byte)[32]byte
	hasEntrySig, hasBytesSig := false, false
	for _, fn := range fns {
		if strings.Contains(fn.resultType, "[32]byte") {
			if strings.Contains(fn.paramType, "*Entry") {
				hasEntrySig = true
			}
			if strings.Contains(fn.paramType, "[]byte") {
				hasBytesSig = true
			}
		}
	}
	s.checks = append(s.checks, check{
		id: "E2", name: "At least one EntryLeafHash* has canonical signature",
		passed: hasEntrySig || hasBytesSig, critical: true,
		detail: fmt.Sprintf("*Entry→[32]byte=%v []byte→[32]byte=%v", hasEntrySig, hasBytesSig),
	})

	// E3: every function uses sha256 (or rfc6962 package imported)
	allSHA := true
	for _, fn := range fns {
		if !fn.usesSHA256 {
			allSHA = false
		}
	}
	s.checks = append(s.checks, check{
		id: "E3", name: "All EntryLeafHash* functions use sha256 (or rfc6962)",
		passed: allSHA || importsRFC6962, critical: true,
		detail: fmt.Sprintf("allSHA=%v importsRFC6962=%v", allSHA, importsRFC6962),
	})

	// E4: every function uses 0x00 or RFC6962LeafPrefix (or rfc6962 package imported)
	allZero := true
	for _, fn := range fns {
		if !fn.usesZero {
			allZero = false
		}
	}
	s.checks = append(s.checks, check{
		id: "E4", name: "All EntryLeafHash* functions use 0x00 / RFC6962LeafPrefix",
		passed: allZero || importsRFC6962, critical: true,
		detail: fmt.Sprintf("allHaveZero=%v importsRFC6962=%v", allZero, importsRFC6962),
	})

	// E5 (new): if cross_log uses EntryLeafHashBytes, we should have a
	// []byte variant. Informational.
	s.checks = append(s.checks, check{
		id: "E5", name: "EntryLeafHashBytes variant exists (informational — cross_log convenience)",
		passed: hasBytesSig, critical: false,
		detail: fmt.Sprintf("bytesVariantExists=%v", hasBytesSig),
	})

	return s
}

// ═══ Suite 3: tests (informational) ═══════════════════════════════

func validateTests(sdkRoot string) suite {
	s := suite{title: "Suite 3 — tests/ (negative tests — informational)"}
	candidates := []string{
		filepath.Join(sdkRoot, "tests"),
		filepath.Join(sdkRoot, "verifier"),
	}
	var testFile string
	for _, dir := range candidates {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || testFile != "" || info == nil || info.IsDir() {
				return nil
			}
			name := filepath.Base(path)
			if strings.HasSuffix(name, "_test.go") &&
				(strings.Contains(name, "cross_log") || strings.Contains(name, "crosslog")) {
				testFile = path
			}
			return nil
		})
		if testFile != "" {
			break
		}
	}

	if testFile == "" {
		s.checks = append(s.checks, check{id: "T1", name: "cross-log test file exists", critical: false,
			detail: "no *cross_log*_test.go found"})
		return s
	}

	s.file = testFile
	s.checks = append(s.checks, check{id: "T1", name: "cross-log test file exists",
		passed: true, critical: false, detail: filepath.Base(testFile)})

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, testFile, nil, parser.ParseComments)
	if err != nil {
		s.checks = append(s.checks, check{id: "T2", name: "test file parses", critical: false, detail: err.Error()})
		return s
	}

	var allTests, negTests []string
	keywords := []string{"Invalid", "Mismatch", "Fraud", "Forged", "Reject", "Wrong", "Bad", "Tampered", "Error", "Fail"}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !strings.HasPrefix(fn.Name.Name, "Test") {
			continue
		}
		allTests = append(allTests, fn.Name.Name)
		for _, kw := range keywords {
			if strings.Contains(fn.Name.Name, kw) {
				negTests = append(negTests, fn.Name.Name)
				break
			}
		}
	}
	s.checks = append(s.checks, check{
		id: "T2", name: "Negative tests present",
		passed: len(negTests) > 0, critical: false,
		detail: fmt.Sprintf("total=%d negative=%d [%s]", len(allTests), len(negTests), strings.Join(negTests, ",")),
	})

	// T3 (new, informational): tests that exercise the CONTENT binding specifically
	// by name — "AnchorContent", "AnchorPayload", "ForgedAnchor" etc.
	contentBindingKeywords := []string{"AnchorContent", "AnchorPayload", "AnchorForged", "ContentBinding", "HashBinding"}
	var bindingTests []string
	for _, t := range allTests {
		for _, kw := range contentBindingKeywords {
			if strings.Contains(t, kw) {
				bindingTests = append(bindingTests, t)
				break
			}
		}
	}
	s.checks = append(s.checks, check{
		id: "T3", name: "Tests specifically exercise content binding (informational)",
		passed: len(bindingTests) > 0, critical: false,
		detail: fmt.Sprintf("bindingTests=%v", bindingTests),
	})

	return s
}

// ═══ AST helpers ═══════════════════════════════════════════════════

func countQualifiedCalls(root ast.Node, pkg, name string) int {
	count := 0
	ast.Inspect(root, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if pkgIdent.Name == pkg && sel.Sel.Name == name {
			count++
		}
		return true
	})
	return count
}

func hasChainedSelector(root ast.Node, outer, inner string) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if found {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name != inner {
			return true
		}
		innerSel, ok := sel.X.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if innerSel.Sel.Name == outer {
			found = true
		}
		return true
	})
	return found
}

func hasSelectorWithName(root ast.Node, name string) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if found {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == name {
			found = true
		}
		return true
	})
	return found
}

func hasBindingComparison(root ast.Node, structPart, structField, targetField string) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if found {
			return false
		}
		be, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		if be.Op != token.EQL && be.Op != token.NEQ {
			return true
		}
		l := exprString(be.X)
		r := exprString(be.Y)
		lStruct := strings.Contains(l, structPart) && strings.Contains(l, structField)
		lTarget := strings.Contains(l, targetField)
		rStruct := strings.Contains(r, structPart) && strings.Contains(r, structField)
		rTarget := strings.Contains(r, targetField)
		if (lStruct && rTarget) || (rStruct && lTarget) {
			found = true
		}
		return true
	})
	return found
}

func countIdentifierUse(root ast.Node, name string) int {
	count := 0
	ast.Inspect(root, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if ident.Name == name {
			count++
		}
		return true
	})
	return count
}

func hasMethodCallOn(root ast.Node, receiver, method string) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name != method {
			return true
		}
		recvIdent, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if recvIdent.Name == receiver {
			found = true
		}
		return true
	})
	return found
}

func hasIntLiteralZero(root ast.Node) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if found {
			return false
		}
		lit, ok := n.(*ast.BasicLit)
		if !ok {
			return true
		}
		if lit.Kind != token.INT {
			return true
		}
		v := lit.Value
		if v == "0" || v == "0x0" || v == "0x00" || v == "0X00" || v == "00" {
			found = true
		}
		return true
	})
	return found
}

func exprString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return exprString(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return "*" + exprString(t.X)
	case *ast.ArrayType:
		if t.Len == nil {
			return "[]" + exprString(t.Elt)
		}
		return "[" + exprString(t.Len) + "]" + exprString(t.Elt)
	case *ast.BasicLit:
		return t.Value
	case *ast.IndexExpr:
		return exprString(t.X) + "[" + exprString(t.Index) + "]"
	case *ast.SliceExpr:
		return exprString(t.X) + "[:]"
	case *ast.CallExpr:
		return exprString(t.Fun) + "(...)"
	default:
		return fmt.Sprintf("%T", expr)
	}
}
