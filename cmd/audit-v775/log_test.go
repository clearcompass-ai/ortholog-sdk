package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// chdirToTemp switches cwd to a fresh tempdir for the duration of
// the test. Returns a cleanup func the caller defers.
func chdirToTemp(t *testing.T) func() {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	return func() { _ = os.Chdir(cwd) }
}

func TestAppendAuditLog_CreatesFileAndHeader(t *testing.T) {
	defer chdirToTemp(t)()
	results := []AuditResult{
		{Registry: "crypto/artifact/pre.mutation-audit.yaml", Gate: "muEnableFoo", Result: "PASS"},
	}
	ts := time.Date(2026, 4, 24, 10, 15, 3, 0, time.UTC)
	path, err := AppendAuditLog(results, ts)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if filepath.Base(path) != "mutation-audit-log.md" {
		t.Fatalf("wrong filename: %s", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(content)
	must := []string{
		"# Mutation-audit log",
		"**PASS** — gate was flipped",
		"2026-04-24T10:15:03Z — audit-v775 mutation",
		"| Registry | Gate | Result | Note |",
		"| crypto/artifact/pre.mutation-audit.yaml | muEnableFoo | PASS | — |",
	}
	for _, m := range must {
		if !strings.Contains(s, m) {
			t.Errorf("missing %q in log:\n%s", m, s)
		}
	}
}

func TestAppendAuditLog_AppendsToExisting(t *testing.T) {
	defer chdirToTemp(t)()
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	if _, err := AppendAuditLog([]AuditResult{{Gate: "muA", Result: "PASS"}}, t1); err != nil {
		t.Fatalf("append 1: %v", err)
	}
	if _, err := AppendAuditLog([]AuditResult{{Gate: "muB", Result: "FAIL", Note: "boom"}}, t2); err != nil {
		t.Fatalf("append 2: %v", err)
	}
	content, err := os.ReadFile(filepath.Join("docs", "audit", "mutation-audit-log.md"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(content)
	// Header appears only once.
	if strings.Count(s, "# Mutation-audit log") != 1 {
		t.Fatalf("header repeated:\n%s", s)
	}
	// Both dated sections present in order.
	idx1 := strings.Index(s, "2026-01-01T00:00:00Z")
	idx2 := strings.Index(s, "2026-01-02T00:00:00Z")
	if idx1 < 0 || idx2 < 0 || idx1 > idx2 {
		t.Fatalf("sections missing or out of order: %d %d\n%s", idx1, idx2, s)
	}
	if !strings.Contains(s, "| muB | FAIL | boom |") {
		t.Fatalf("failure note missing:\n%s", s)
	}
}

func TestOneLine_FlattensNewlines(t *testing.T) {
	got := oneLine("line1\nline2\nline3")
	if got != "line1 / line2 / line3" {
		t.Fatalf("got %q", got)
	}
}

func TestOneLine_EscapesPipes(t *testing.T) {
	got := oneLine("col1 | col2")
	if !strings.Contains(got, `\|`) {
		t.Fatalf("pipe not escaped: %q", got)
	}
}

func TestOneLine_EmptyReturnsEmdash(t *testing.T) {
	if got := oneLine(""); got != "—" {
		t.Fatalf("empty did not return emdash: %q", got)
	}
	if got := oneLine("   "); got != "—" {
		t.Fatalf("whitespace did not return emdash: %q", got)
	}
}
