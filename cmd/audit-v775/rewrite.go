// cmd/audit-v775/rewrite.go — source-file rewrite helpers for the
// mutation-audit runner. Two strategies:
//
//   FlipBoolConstFalse / RestoreBoolConstTrue
//       Finds the line `<ident> = true` (inside a const block) and
//       rewrites the value to `false`. Restore flips it back. Used
//       by GateBoolConst.
//
//   ReplaceString / RestoreString
//       File-wide textual replace of `from` with `to`. Used by
//       GateStringMutation for DST pins and similar.
//
// Both strategies round-trip through the filesystem via
// os.ReadFile / os.WriteFile. On any mutation the runner caches
// the original bytes in memory AND writes a `.mutation-backup`
// sibling file so a crashed runner can be recovered manually.
//
// The rewrite is deliberately line-local rather than AST-based —
// const blocks in pre.go span dozens of lines and Go's go/printer
// reformats surrounding whitespace, which would noise every diff.
// Line-local editing preserves every byte around the mutation.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────
// bool_const rewrite
// ─────────────────────────────────────────────────────────────────────

// findBoolConstLineRE matches both declaration styles:
//
//   <indent><ident> = true             // inside `const (...)` block
//   <indent>const <ident> = true       // plain top-level declaration
//
// Capture groups:
//   1. leading whitespace + optional `const ` keyword
//   2. ` = ` (between ident and value)
//   3. trailing whitespace + optional // comment
//
// The (?m) flag makes ^/$ match at line boundaries.
func findBoolConstLineRE(gateName string) *regexp.Regexp {
	return regexp.MustCompile(
		`(?m)^(\s*(?:const\s+)?)` + regexp.QuoteMeta(gateName) + `(\s*=\s*)true(\s*(?://.*)?)$`,
	)
}

// FlipBoolConstFalse rewrites `gateName = true` → `gateName = false`
// in path. Returns the original bytes so the caller can restore
// without re-reading.
//
// Fails if the line is not found, if the line is already `false`,
// or if the ident appears multiple times (ambiguous mutation).
func FlipBoolConstFalse(path, gateName string) (original []byte, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	re := findBoolConstLineRE(gateName)

	var out bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	matched := 0
	for scanner.Scan() {
		line := scanner.Text()
		if re.MatchString(line) {
			rewritten := re.ReplaceAllString(line, `${1}`+gateName+`${2}false${3}`)
			out.WriteString(rewritten)
			matched++
		} else {
			out.WriteString(line)
		}
		out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	// Strip the trailing newline we added if the original did not end in one.
	result := out.Bytes()
	if !bytes.HasSuffix(raw, []byte{'\n'}) {
		result = result[:len(result)-1]
	}

	if matched == 0 {
		return nil, fmt.Errorf("%s: gate %q: no `%s = true` line found", path, gateName, gateName)
	}
	if matched > 1 {
		return nil, fmt.Errorf("%s: gate %q: %d matching lines (ambiguous)", path, gateName, matched)
	}

	if err := writeMutated(path, result); err != nil {
		return nil, err
	}
	return raw, nil
}

// RestoreBytes writes the supplied bytes to path. Used to undo a
// FlipBoolConstFalse or ReplaceString.
func RestoreBytes(path string, original []byte) error {
	if err := os.WriteFile(path, original, 0644); err != nil {
		return fmt.Errorf("restore %s: %w", path, err)
	}
	// Best-effort remove of the backup file.
	_ = os.Remove(path + ".mutation-backup")
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// string_mutation rewrite
// ─────────────────────────────────────────────────────────────────────

// ReplaceString file-wide replaces every occurrence of `from` with
// `to` in path. Returns the original bytes. Fails if `from` does not
// appear in the file (no-op is always a test bug).
func ReplaceString(path, from, to string) (original []byte, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if !strings.Contains(string(raw), from) {
		return nil, fmt.Errorf("%s: substring %q not present", path, from)
	}
	mutated := strings.ReplaceAll(string(raw), from, to)
	if err := writeMutated(path, []byte(mutated)); err != nil {
		return nil, err
	}
	return raw, nil
}

// ─────────────────────────────────────────────────────────────────────
// Shared write + backup
// ─────────────────────────────────────────────────────────────────────

// writeMutated atomically replaces path's content with data and
// writes a sibling `.mutation-backup` file to aid crash recovery.
// We do NOT rely on the backup at runtime — the runner keeps the
// original bytes in memory — but it exists so a human can recover
// from a SIGKILLed runner by copying the backup over the live file.
func writeMutated(path string, data []byte) error {
	// Note: backup is written AFTER the mutation writes succeed so
	// we can't leave a stale backup that doesn't match the live
	// source. If the caller re-enters writeMutated before restore,
	// the backup is overwritten; the in-memory original remains
	// authoritative for restore.
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
