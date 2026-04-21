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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <path-to-scan>")
		os.Exit(1)
	}
	scanPath := os.Args[1]

	fset := token.NewFileSet()
	hasViolations := false

	err := filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}

		ast.Inspect(f, func(n ast.Node) bool {
			// We are looking for binary expressions: A != B or A == B
			binExpr, ok := n.(*ast.BinaryExpr)
			if !ok {
				return true
			}

			if binExpr.Op == token.NEQ || binExpr.Op == token.EQL {
				// Check if one side is `CosignatureOf` and the other is `nil`
				if isCosignatureOfNilCheck(binExpr.X, binExpr.Y) || isCosignatureOfNilCheck(binExpr.Y, binExpr.X) {
					pos := fset.Position(binExpr.Pos())

					// WHITELIST: Allow the check inside the helper function itself.
					// Adjust the filename here to match where you put IsCosignatureOf.
					if strings.HasSuffix(pos.Filename, "verifier/cosignature_helper.go") {
						return true
					}

					fmt.Printf("❌ SECURITY VIOLATION at %s\n", pos)
					fmt.Printf("   Detected raw un-bound check: '%s'\n", formatNode(fset, binExpr))
					fmt.Printf("   Fix: Use verifier.IsCosignatureOf(entry, expectedPos) to ensure cryptographic binding.\n\n")

					hasViolations = true
				}
			}
			return true
		})
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}

	if hasViolations {
		fmt.Println("🚨 AST Check Failed: Un-bound CosignatureOf checks detected.")
		os.Exit(1)
	}

	fmt.Println("✅ AST Check Passed: No un-bound CosignatureOf checks found.")
}

// isCosignatureOfNilCheck returns true if exprA is a selector ending in "CosignatureOf"
// and exprB is the identifier "nil".
func isCosignatureOfNilCheck(exprA, exprB ast.Expr) bool {
	return isCosignatureOfField(exprA) && isNilIdent(exprB)
}

// isCosignatureOfField checks if the expression evaluates to the CosignatureOf field.
func isCosignatureOfField(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel.Name == "CosignatureOf"
}

// isNilIdent checks if the expression is the literal `nil`.
func isNilIdent(e ast.Expr) bool {
	ident, ok := e.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "nil"
}

// formatNode is a quick helper to print the offending snippet.
func formatNode(fset *token.FileSet, node ast.Node) string {
	start := fset.Position(node.Pos()).Offset
	end := fset.Position(node.End()).Offset

	// Open the file and extract the snippet (ignoring errors for brevity in this linter)
	content, err := os.ReadFile(fset.Position(node.Pos()).Filename)
	if err != nil || start >= len(content) || end > len(content) {
		return "CosignatureOf != nil"
	}
	return string(content[start:end])
}
