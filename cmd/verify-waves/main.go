// cmd/verify-waves/main.go
//
// Run from repo root: go run cmd/verify-waves/main.go
//
// Verifies every structural change made in Wave 1.5, Wave 2, and Wave 3.
// Emits [✓] for passes, [✗] for failures, [!] for file-level errors.
// Exits with code 0 iff every assertion passed.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
)

var (
	pass int
	fail int
)

func main() {
	fmt.Println("=== Ortholog SDK — Wave 1.5, Wave 2, Wave 3 AST Verification ===")
	fmt.Println()
	fset := token.NewFileSet()

	verifyWave15(fset)
	verifyWave2(fset)
	verifyWave3(fset)

	fmt.Println()
	fmt.Printf("=== Summary: %d passed, %d failed ===\n", pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

// ══════════════════════════════════════════════════════════════════════
// Wave 1.5 — DomainManifestVersion removal
// ══════════════════════════════════════════════════════════════════════

func verifyWave15(fset *token.FileSet) {
	fmt.Println("── Wave 1.5 — DomainManifestVersion removal ───────────────────────")

	if node := parseFile(fset, "core/envelope/control_header.go"); node != nil {
		fmt.Println("[Wave 1.5] core/envelope/control_header.go")
		assert(!hasField(node, "ControlHeader", "DomainManifestVersion"),
			"ControlHeader.DomainManifestVersion removed")
	}

	if node := parseFile(fset, "core/envelope/serialize.go"); node != nil {
		fmt.Println("[Wave 1.5] core/envelope/serialize.go")
		assert(!hasFunc(node, "appendOptionalManifestVersion"),
			"appendOptionalManifestVersion removed")
		assert(!hasFunc(node, "readOptionalManifestVersion"),
			"readOptionalManifestVersion removed")
		assert(!hasVar(node, "ErrManifestVersionNonZeroSlot"),
			"ErrManifestVersionNonZeroSlot removed")
		assert(!hasIdentRef(node, "manifestVersionBytes"),
			"manifestVersionBytes no longer referenced")
		assert(!hasIdentRef(node, "DomainManifestVersion"),
			"DomainManifestVersion no longer referenced")
		assert(singleParamDeserializeHeaderBody(node),
			"deserializeHeaderBody takes single []byte arg (version param removed)")
	}

	if node := parseFile(fset, "core/envelope/api.go"); node != nil {
		fmt.Println("[Wave 1.5] core/envelope/api.go")
		assert(!hasConst(node, "manifestVersionBytes"),
			"manifestVersionBytes constant removed")
	}

	if node := parseFile(fset, "tests/envelope_v5_test.go"); node != nil {
		fmt.Println("[Wave 1.5] tests/envelope_v5_test.go")
		assert(!hasFunc(node, "TestV5_RoundTripWithManifestVersion"),
			"TestV5_RoundTripWithManifestVersion deleted")
		assert(!hasFunc(node, "TestV5_RoundTripWithoutManifestVersion"),
			"TestV5_RoundTripWithoutManifestVersion deleted")
		assert(!hasFunc(node, "TestV5_CanonicalHashCoversManifestVersion"),
			"TestV5_CanonicalHashCoversManifestVersion deleted")
		// New round-trip canary
		assert(hasFunc(node, "TestV5_RoundTripPreservesAllFields"),
			"TestV5_RoundTripPreservesAllFields added as field churn canary")
	}
}

// ══════════════════════════════════════════════════════════════════════
// Wave 2 — Schema-driven override threshold + typed ProposalType
// ══════════════════════════════════════════════════════════════════════

func verifyWave2(fset *token.FileSet) {
	fmt.Println()
	fmt.Println("── Wave 2 — Schema-driven thresholds + typed ProposalType ─────────")

	if node := parseFile(fset, "types/schema_parameters.go"); node != nil {
		fmt.Println("[Wave 2] types/schema_parameters.go")
		assert(hasType(node, "OverrideThresholdRule"),
			"OverrideThresholdRule type defined")
		assert(hasConst(node, "ThresholdTwoThirdsMajority"),
			"ThresholdTwoThirdsMajority const defined")
		assert(hasConst(node, "ThresholdSimpleMajority"),
			"ThresholdSimpleMajority const defined")
		assert(hasConst(node, "ThresholdUnanimity"),
			"ThresholdUnanimity const defined")
		assert(hasMethod(node, "OverrideThresholdRule", "RequiredApprovals"),
			"OverrideThresholdRule.RequiredApprovals method defined")
		assert(hasMethod(node, "OverrideThresholdRule", "String"),
			"OverrideThresholdRule.String method defined")
		assert(hasField(node, "SchemaParameters", "OverrideThreshold"),
			"SchemaParameters.OverrideThreshold field exists")
		assert(fieldType(node, "SchemaParameters", "OverrideThreshold") == "OverrideThresholdRule",
			"SchemaParameters.OverrideThreshold typed as OverrideThresholdRule")
	}

	if node := parseFile(fset, "schema/parameters_json.go"); node != nil {
		fmt.Println("[Wave 2] schema/parameters_json.go")
		assert(hasField(node, "jsonSchemaPayload", "OverrideThreshold"),
			"jsonSchemaPayload.OverrideThreshold field exists")
		assert(fieldType(node, "jsonSchemaPayload", "OverrideThreshold") == "*string",
			"jsonSchemaPayload.OverrideThreshold is *string")
		assert(hasStringLit(node, "two_thirds"),
			"parser recognizes \"two_thirds\"")
		assert(hasStringLit(node, "simple_majority"),
			"parser recognizes \"simple_majority\"")
		assert(hasStringLit(node, "unanimity"),
			"parser recognizes \"unanimity\"")
	}

	if node := parseFile(fset, "verifier/contest_override.go"); node != nil {
		fmt.Println("[Wave 2] verifier/contest_override.go")
		assert(!hasMathCeil(node),
			"math.Ceil hardcoding removed")
		assert(hasCallExpr(node, "RequiredApprovals"),
			"RequiredApprovals() is called")
	}

	if node := parseFile(fset, "lifecycle/recovery.go"); node != nil {
		fmt.Println("[Wave 2] lifecycle/recovery.go")
		assert(!hasMathCeil(node),
			"math.Ceil hardcoding removed")
		assert(hasCallExpr(node, "RequiredApprovals"),
			"RequiredApprovals() is called in EvaluateArbitration")
	}

	if node := parseFile(fset, "lifecycle/scope_governance.go"); node != nil {
		fmt.Println("[Wave 2] lifecycle/scope_governance.go")
		assert(hasType(node, "ProposalType"),
			"ProposalType type defined")
		assert(hasConst(node, "ProposalAddAuthority"),
			"ProposalAddAuthority const defined")
		assert(hasConst(node, "ProposalRemoveAuthority"),
			"ProposalRemoveAuthority const defined")
		assert(hasConst(node, "ProposalChangeParameters"),
			"ProposalChangeParameters const defined")
		assert(hasConst(node, "ProposalDomainExtension"),
			"ProposalDomainExtension const defined")
		assert(hasMethod(node, "ProposalType", "String"),
			"ProposalType.String method defined")
		assert(fieldType(node, "AmendmentProposalParams", "ProposalType") == "ProposalType",
			"AmendmentProposalParams.ProposalType is typed enum (not string)")
	}
}

// ══════════════════════════════════════════════════════════════════════
// Wave 3 — Domain extraction (judicial concepts removed from SDK)
// ══════════════════════════════════════════════════════════════════════

func verifyWave3(fset *token.FileSet) {
	fmt.Println()
	fmt.Println("── Wave 3 — Domain extraction ──────────────────────────────────────")

	if node := parseFile(fset, "lifecycle/provision.go"); node != nil {
		fmt.Println("[Wave 3] lifecycle/provision.go")
		assert(!hasFunc(node, "ProvisionThreeLogs"),
			"ProvisionThreeLogs deleted")
		assert(!hasFunc(node, "provisionLog"),
			"provisionLog helper inlined/removed")
		assert(!hasFunc(node, "containsLogDID"),
			"containsLogDID helper removed")
		assert(!hasType(node, "ProvisionConfig"),
			"ProvisionConfig type deleted")
		assert(!hasType(node, "ProvisionResult"),
			"ProvisionResult type deleted")
		assert(hasFunc(node, "ProvisionSingleLog"),
			"ProvisionSingleLog retained")
		assert(hasType(node, "SingleLogConfig"),
			"SingleLogConfig retained")
		assert(hasType(node, "LogProvision"),
			"LogProvision retained")
		assert(!hasField(node, "DelegationSpec", "LogDIDs"),
			"DelegationSpec.LogDIDs judicial field removed")
		assert(!hasField(node, "SchemaSpec", "LogDID"),
			"SchemaSpec.LogDID judicial field removed")
		assert(!hasIdentRef(node, "CourtDID"),
			"CourtDID reference removed")
		assert(!hasIdentRef(node, "OfficersLogDID"),
			"OfficersLogDID reference removed")
		assert(!hasIdentRef(node, "CasesLogDID"),
			"CasesLogDID reference removed")
		assert(!hasIdentRef(node, "PartiesLogDID"),
			"PartiesLogDID reference removed")
	}

	if node := parseFile(fset, "did/vendor_did.go"); node != nil {
		fmt.Println("[Wave 3] did/vendor_did.go")
		assert(!hasFunc(node, "CourtMapping"),
			"CourtMapping deleted")
		assert(!hasFunc(node, "JNetMapping"),
			"JNetMapping deleted")
		assert(!hasFunc(node, "CCRMapping"),
			"CCRMapping deleted")
		assert(hasType(node, "VendorDIDResolver"),
			"VendorDIDResolver infrastructure retained")
		assert(hasType(node, "VendorMapping"),
			"VendorMapping infrastructure retained")
		assert(hasFunc(node, "NewVendorDIDResolver"),
			"NewVendorDIDResolver constructor retained")
	}

	// Test file also needs updating
	if node := parseFile(fset, "tests/vendor_did_test.go"); node != nil {
		fmt.Println("[Wave 3] tests/vendor_did_test.go")
		assert(!hasCallExpr(node, "CourtMapping"),
			"CourtMapping no longer called in tests")
		assert(!hasCallExpr(node, "JNetMapping"),
			"JNetMapping no longer called in tests")
		assert(!hasCallExpr(node, "CCRMapping"),
			"CCRMapping no longer called in tests")
	}
}

// ══════════════════════════════════════════════════════════════════════
// AST Helpers
// ══════════════════════════════════════════════════════════════════════

func parseFile(fset *token.FileSet, path string) *ast.File {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Printf("  [!] FILE NOT FOUND: %s\n", path)
		return nil
	}
	node, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
	if err != nil {
		fmt.Printf("  [!] ERROR PARSING %s: %v\n", path, err)
		return nil
	}
	return node
}

func assert(cond bool, msg string) {
	if cond {
		pass++
		fmt.Printf("  [✓] PASS: %s\n", msg)
	} else {
		fail++
		fmt.Printf("  [✗] FAIL: %s\n", msg)
	}
}

// hasType: top-level type declaration of given name.
func hasType(node *ast.File, name string) bool {
	for _, d := range node.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, s := range gd.Specs {
			if ts, ok := s.(*ast.TypeSpec); ok && ts.Name.Name == name {
				return true
			}
		}
	}
	return false
}

// hasConst: top-level const declaration of given name.
func hasConst(node *ast.File, name string) bool {
	for _, d := range node.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, s := range gd.Specs {
			vs, ok := s.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, id := range vs.Names {
				if id.Name == name {
					return true
				}
			}
		}
	}
	return false
}

// hasVar: top-level var declaration of given name.
func hasVar(node *ast.File, name string) bool {
	for _, d := range node.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, s := range gd.Specs {
			vs, ok := s.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, id := range vs.Names {
				if id.Name == name {
					return true
				}
			}
		}
	}
	return false
}

// hasFunc: top-level function (no receiver) of given name.
func hasFunc(node *ast.File, name string) bool {
	for _, d := range node.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == name {
			return true
		}
	}
	return false
}

// hasMethod: method on (value or pointer) receiver of given type name.
func hasMethod(node *ast.File, recvType, method string) bool {
	for _, d := range node.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || fd.Name.Name != method {
			continue
		}
		for _, field := range fd.Recv.List {
			// Unwrap pointer receiver
			t := field.Type
			if star, ok := t.(*ast.StarExpr); ok {
				t = star.X
			}
			if ident, ok := t.(*ast.Ident); ok && ident.Name == recvType {
				return true
			}
		}
	}
	return false
}

// hasField: struct has a field of given name (type-agnostic).
func hasField(node *ast.File, structName, fieldName string) bool {
	return findField(node, structName, fieldName) != nil
}

// fieldType: returns the type expression for the field, or "" if absent.
func fieldType(node *ast.File, structName, fieldName string) string {
	f := findField(node, structName, fieldName)
	if f == nil {
		return ""
	}
	return typeToString(f.Type)
}

func findField(node *ast.File, structName, fieldName string) *ast.Field {
	for _, d := range node.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, s := range gd.Specs {
			ts, ok := s.(*ast.TypeSpec)
			if !ok || ts.Name.Name != structName {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			for _, field := range st.Fields.List {
				for _, name := range field.Names {
					if name.Name == fieldName {
						return field
					}
				}
			}
		}
	}
	return nil
}

// hasMathCeil: any call to math.Ceil in the file.
func hasMathCeil(node *ast.File) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if id.Name == "math" && sel.Sel.Name == "Ceil" {
			found = true
			return false
		}
		return true
	})
	return found
}

// hasCallExpr: any call to a method or function named `name`.
// Matches both `x.name(...)` and `name(...)` forms.
func hasCallExpr(node *ast.File, name string) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			if fn.Sel.Name == name {
				found = true
			}
		case *ast.Ident:
			if fn.Name == name {
				found = true
			}
		}
		return !found
	})
	return found
}

// hasIdentRef: any Ident with the given name anywhere in the file,
// excluding imports and package declarations. Useful for confirming
// a removed symbol has no residual references.
func hasIdentRef(node *ast.File, name string) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}

// hasStringLit: file contains a basic literal string equal to `s`.
func hasStringLit(node *ast.File, s string) bool {
	target := `"` + s + `"`
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && lit.Value == target {
			found = true
			return false
		}
		return true
	})
	return found
}

// singleParamDeserializeHeaderBody: verifies Wave 1.5 removed the
// `version` parameter from deserializeHeaderBody.
func singleParamDeserializeHeaderBody(node *ast.File) bool {
	for _, d := range node.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name.Name != "deserializeHeaderBody" {
			continue
		}
		if fd.Type.Params == nil {
			return false
		}
		// Count total param names (handles grouped `a, b T` signatures).
		count := 0
		for _, field := range fd.Type.Params.List {
			if len(field.Names) == 0 {
				count++
			} else {
				count += len(field.Names)
			}
		}
		return count == 1
	}
	return false
}

func typeToString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + typeToString(t.X)
	case *ast.ArrayType:
		return "[]" + typeToString(t.Elt)
	case *ast.SelectorExpr:
		return typeToString(t.X) + "." + t.Sel.Name
	case *ast.MapType:
		return "map[" + typeToString(t.Key) + "]" + typeToString(t.Value)
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.FuncType:
		return "func"
	default:
		return ""
	}
}
