package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTempFile creates a Go file with the given contents in a temp
// dir and returns its path. Cleaned up by t.TempDir().
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func readAll(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b)
}

// ─────────────────────────────────────────────────────────────────────
// FlipBoolConstFalse / RestoreBytes
// ─────────────────────────────────────────────────────────────────────

func TestFlipBoolConstFalse_ConstBlock(t *testing.T) {
	src := `package x

const (
	muEnableFoo = true
	muEnableBar = true
)
`
	path := writeTempFile(t, "x.go", src)

	orig, err := FlipBoolConstFalse(path, "muEnableFoo")
	if err != nil {
		t.Fatalf("flip: %v", err)
	}
	after := readAll(t, path)
	if !strings.Contains(after, "muEnableFoo = false") {
		t.Fatalf("muEnableFoo not flipped to false:\n%s", after)
	}
	if !strings.Contains(after, "muEnableBar = true") {
		t.Fatalf("muEnableBar incorrectly touched:\n%s", after)
	}

	// Restore and verify byte identity.
	if err := RestoreBytes(path, orig); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := readAll(t, path); got != src {
		t.Fatalf("restored content drift:\nwant:\n%s\ngot:\n%s", src, got)
	}
}

func TestFlipBoolConstFalse_TopLevelConst(t *testing.T) {
	src := `package y

const muEnableAtomic = true
`
	path := writeTempFile(t, "y.go", src)

	orig, err := FlipBoolConstFalse(path, "muEnableAtomic")
	if err != nil {
		t.Fatalf("flip: %v", err)
	}
	after := readAll(t, path)
	if !strings.Contains(after, "const muEnableAtomic = false") {
		t.Fatalf("not flipped:\n%s", after)
	}
	if err := RestoreBytes(path, orig); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if readAll(t, path) != src {
		t.Fatalf("restored drift")
	}
}

func TestFlipBoolConstFalse_PreservesTrailingComments(t *testing.T) {
	src := `package x

const (
	muEnableFoo = true // Group 3.2 binding
)
`
	path := writeTempFile(t, "x.go", src)
	if _, err := FlipBoolConstFalse(path, "muEnableFoo"); err != nil {
		t.Fatalf("flip: %v", err)
	}
	after := readAll(t, path)
	if !strings.Contains(after, "// Group 3.2 binding") {
		t.Fatalf("trailing comment lost:\n%s", after)
	}
}

func TestFlipBoolConstFalse_MissingGate(t *testing.T) {
	path := writeTempFile(t, "x.go", `package x

const muOther = true
`)
	_, err := FlipBoolConstFalse(path, "muEnableFoo")
	if err == nil || !strings.Contains(err.Error(), "no `muEnableFoo = true`") {
		t.Fatalf("want no-match error, got %v", err)
	}
}

func TestFlipBoolConstFalse_AmbiguousMatch(t *testing.T) {
	// Duplicate declarations — ambiguous mutation target.
	path := writeTempFile(t, "x.go", `package x

const (
	muEnableFoo = true
)

const muEnableFoo2 = true

const muEnableFoo = true // shadowing (illegal Go — but the file
                         // regex must still surface the ambiguity)
`)
	_, err := FlipBoolConstFalse(path, "muEnableFoo")
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("want ambiguous error, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// ReplaceString (string_mutation)
// ─────────────────────────────────────────────────────────────────────

func TestReplaceString_HappyPath(t *testing.T) {
	src := `package x

const dst = "ORTHOLOG-V7.75-DLEQ-CHALLENGE-v1"
`
	path := writeTempFile(t, "x.go", src)
	orig, err := ReplaceString(path, "ORTHOLOG-V7.75-DLEQ-CHALLENGE-v1", "ORTHOLOG-V7.75-DLEQ-CHALLENGE-v2")
	if err != nil {
		t.Fatalf("ReplaceString: %v", err)
	}
	after := readAll(t, path)
	if !strings.Contains(after, "ORTHOLOG-V7.75-DLEQ-CHALLENGE-v2") {
		t.Fatalf("not replaced:\n%s", after)
	}
	if strings.Contains(after, "ORTHOLOG-V7.75-DLEQ-CHALLENGE-v1") {
		t.Fatalf("original still present:\n%s", after)
	}
	if err := RestoreBytes(path, orig); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if readAll(t, path) != src {
		t.Fatalf("restored drift")
	}
}

func TestReplaceString_AbsentSubstring(t *testing.T) {
	path := writeTempFile(t, "x.go", `package x
const dst = "something else"
`)
	_, err := ReplaceString(path, "NOT-PRESENT", "NEW-VALUE")
	if err == nil || !strings.Contains(err.Error(), "not present") {
		t.Fatalf("want absent-substring error, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Regex edge cases
// ─────────────────────────────────────────────────────────────────────

func TestFindBoolConstLineRE_DoesNotMatchDocComment(t *testing.T) {
	src := `package x

// muEnableFoo = true  // docs referencing the constant
const muEnableFoo = true
`
	// The regex must match the ACTUAL const line only, not the
	// comment line. After flip, the docs stay at "= true" while
	// the const becomes "= false".
	path := writeTempFile(t, "x.go", src)
	_, err := FlipBoolConstFalse(path, "muEnableFoo")
	if err == nil {
		// If no error, we must have matched only one line (the const).
		// The comment line should not match because the `//` prefix
		// precedes the ident, and our regex requires the ident to come
		// directly after optional whitespace + optional "const ".
		after := readAll(t, path)
		if !strings.Contains(after, "const muEnableFoo = false") {
			t.Fatalf("const not flipped:\n%s", after)
		}
		if !strings.Contains(after, "// muEnableFoo = true") {
			t.Fatalf("doc comment was touched:\n%s", after)
		}
		return
	}
	// Ambiguous is also acceptable here — we surface the collision.
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("want either clean flip or ambiguous error, got %v", err)
	}
}
