// cmd/audit-v775/log.go — append-only audit log at
// docs/audit/mutation-audit-log.md. The file records every
// mutation-audit run as a dated markdown section.
//
// Format (canonical):
//
//   ## 2026-04-24T10:15:03Z — audit-v775 mutation
//
//   | Registry                                        | Gate                              | Result |
//   | ----------------------------------------------- | --------------------------------- | ------ |
//   | crypto/artifact/pre.mutation-audit.yaml         | muEnableCommitmentsGate           | PASS   |
//   | crypto/artifact/pre.mutation-audit.yaml         | muEnableDLEQCheck                 | PASS   |
//
// Entries are appended in discovery order (same order the runner
// walked). Each row reports one gate. The runner writes the section
// atomically (tempfile + rename) so a crashed runner never leaves a
// half-formed row.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AuditResult records a single gate's mutation result.
type AuditResult struct {
	Registry string // relative path to the *.mutation-audit.yaml
	Gate     string // gate name
	Result   string // "PASS" | "FAIL" | "SKIP"
	Note     string // optional diagnostic (failure reason, skip rationale)
}

// AppendAuditLog appends a dated section to
// docs/audit/mutation-audit-log.md. Creates the file (with a header)
// if it does not yet exist. Returns the absolute path written.
func AppendAuditLog(results []AuditResult, wallclock time.Time) (string, error) {
	logDir := filepath.Join("docs", "audit")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", logDir, err)
	}
	path := filepath.Join(logDir, "mutation-audit-log.md")

	var header string
	if _, err := os.Stat(path); os.IsNotExist(err) {
		header = logFileHeader()
	}

	var section strings.Builder
	if header != "" {
		section.WriteString(header)
	}
	section.WriteString(renderSection(results, wallclock))

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(section.String()); err != nil {
		return "", fmt.Errorf("append %s: %w", path, err)
	}
	return path, nil
}

func logFileHeader() string {
	return `# Mutation-audit log

Every row records one gate's mutation result from a run of
` + "`cmd/audit-v775 mutation`" + `.

- **PASS** — gate was flipped, listed binding tests failed as expected,
  gate was restored, listed binding tests passed again.
- **FAIL** — discipline broken. Either the mutation did not cause the
  binding tests to fail (the switch is not load-bearing) or the
  restored source did not bring the tests back green (the test suite
  is unstable).
- **SKIP** — gate was filtered out by ` + "`--only`" + ` or the runner
  could not locate the source file (registry drift).

The file is append-only. Entries are committed to the repo.

`
}

func renderSection(results []AuditResult, wallclock time.Time) string {
	var b strings.Builder
	ts := wallclock.UTC().Format(time.RFC3339)
	fmt.Fprintf(&b, "## %s — audit-v775 mutation\n\n", ts)
	fmt.Fprintln(&b, "| Registry | Gate | Result | Note |")
	fmt.Fprintln(&b, "| --- | --- | --- | --- |")
	for _, r := range results {
		note := r.Note
		if note == "" {
			note = "—"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
			r.Registry, r.Gate, r.Result, oneLine(note))
	}
	fmt.Fprintln(&b)
	return b.String()
}

// oneLine flattens a multi-line note to a single line so it fits in
// a markdown table cell. Keeps it human-readable by joining with
// " / " separators.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " / ")
	s = strings.TrimSpace(s)
	if s == "" {
		return "—"
	}
	return s
}
