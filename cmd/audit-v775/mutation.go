// cmd/audit-v775/mutation.go — mutation-audit runner.
//
// For each gate in each *.mutation-audit.yaml registry:
//
//   1. Pre-check: `go test -run <each test>` on the listed binding
//      tests MUST pass. If not, the baseline is broken and we
//      cannot meaningfully mutate — record SKIP with the baseline
//      error and move on.
//
//   2. Mutate: flip the bool_const to false, or replace the
//      mutation_from string with mutation_to. Keep the original
//      bytes in memory so we can always restore even if the test
//      shell-out misbehaves.
//
//   3. Post-mutation test: `go test -run` the same tests. Each
//      listed test MUST fail. If any one passes, the switch is
//      NOT load-bearing — record FAIL and restore.
//
//   4. Restore: write the original bytes back.
//
//   5. Post-restore test: tests MUST pass again. If not, the test
//      suite is non-deterministic — record FAIL.
//
//   6. Append a PASS/FAIL row to docs/audit/mutation-audit-log.md.
//
// Flags parsed in main.go: --validate-registries, --list,
// --dry-run, --only=<regexp>.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// Validation mode lives in mutation_validate.go to keep this file
// focused on the mutation-probe control flow.
// ─────────────────────────────────────────────────────────────────────

func runMutation(args []string) {
	fs := flag.NewFlagSet("mutation", flag.ExitOnError)
	validateOnly := fs.Bool("validate-registries", false, "validate registries; do not mutate")
	listOnly := fs.Bool("list", false, "list every gate and exit")
	dryRun := fs.Bool("dry-run", false, "load registries and prepare but do not mutate or run tests")
	only := fs.String("only", "", "regexp filter on gate names")
	root := fs.String("root", ".", "repository root")
	if err := fs.Parse(args); err != nil {
		fatal("parse flags: %v", err)
	}

	regs, err := LoadAllRegistries(*root)
	if err != nil {
		fatal("load registries: %v", err)
	}
	if len(regs) == 0 {
		fatal("no *.mutation-audit.yaml files found under %s", *root)
	}

	if *listOnly {
		for _, r := range regs {
			for _, g := range r.Gates {
				fmt.Printf("%s\t%s\t%s\n", r.File, g.Name, g.Kind)
			}
		}
		return
	}

	if *validateOnly {
		runValidateRegistries(regs)
		return
	}

	var filter *regexp.Regexp
	if *only != "" {
		filter, err = regexp.Compile(*only)
		if err != nil {
			fatal("bad --only regexp: %v", err)
		}
	}

	results := runAllMutations(regs, filter, *dryRun)
	if len(results) > 0 && !*dryRun {
		logPath, err := AppendAuditLog(results, time.Now())
		if err != nil {
			fatal("append audit log: %v", err)
		}
		fmt.Fprintf(os.Stderr, "audit-v775: appended %d rows to %s\n", len(results), logPath)
	}

	// Exit 4 if any result is FAIL.
	for _, r := range results {
		if r.Result == "FAIL" {
			os.Exit(4)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Runner
// ─────────────────────────────────────────────────────────────────────

func runAllMutations(regs []*Registry, filter *regexp.Regexp, dry bool) []AuditResult {
	var results []AuditResult
	for _, r := range regs {
		for _, g := range r.Gates {
			if filter != nil && !filter.MatchString(g.Name) {
				continue
			}
			res := AuditResult{
				Registry: r.RegistryPath,
				Gate:     g.Name,
				Result:   "SKIP",
				Note:     "",
			}
			if dry {
				res.Note = "dry-run"
				results = append(results, res)
				fmt.Fprintf(os.Stderr, "  SKIP %s/%s (dry-run)\n", r.File, g.Name)
				continue
			}
			runOne(r, g, &res)
			results = append(results, res)
		}
	}
	return results
}

func runOne(r *Registry, g Gate, res *AuditResult) {
	// 1. Baseline test run.
	if err := runTests(r.Package, g.Tests, wantPass); err != nil {
		res.Result = "SKIP"
		res.Note = "baseline failed: " + err.Error()
		fmt.Fprintf(os.Stderr, "  SKIP %s/%s: baseline failed\n", r.File, g.Name)
		return
	}

	// 2. Mutate.
	original, err := mutate(r.File, g)
	if err != nil {
		res.Result = "FAIL"
		res.Note = "mutate failed: " + err.Error()
		fmt.Fprintf(os.Stderr, "  FAIL %s/%s: mutate: %v\n", r.File, g.Name, err)
		return
	}

	// restored is the control flag for the deferred safety-net
	// restore. We set it true after every successful manual
	// restore so the defer is a no-op on the happy path. If any
	// control flow exits runOne before the manual restore — a
	// panic, an unanticipated error return — the defer fires with
	// the captured original bytes and keeps the source tree
	// consistent.
	restored := false
	defer func() {
		if restored {
			return
		}
		if restoreErr := RestoreBytes(r.File, original); restoreErr != nil {
			fmt.Fprintf(os.Stderr,
				"  CRITICAL %s/%s: deferred restore failed: %v\n  Recover manually: git checkout -- %s\n",
				r.File, g.Name, restoreErr, r.File)
			if res.Result != "FAIL" {
				res.Result = "FAIL"
				res.Note = "deferred restore failed: " + restoreErr.Error()
			}
		}
	}()

	// 3. Post-mutation tests — MUST fail.
	if err := runTests(r.Package, g.Tests, wantFail); err != nil {
		res.Result = "FAIL"
		res.Note = "post-mutation: " + err.Error()
		fmt.Fprintf(os.Stderr, "  FAIL %s/%s: post-mutation: %v\n", r.File, g.Name, err)
		return // deferred restore fires
	}

	// 4. Manual restore.
	if restoreErr := RestoreBytes(r.File, original); restoreErr != nil {
		res.Result = "FAIL"
		res.Note = "restore failed: " + restoreErr.Error()
		return // deferred restore will retry
	}
	restored = true

	// 5. Post-restore tests — MUST pass again.
	if err := runTests(r.Package, g.Tests, wantPass); err != nil {
		res.Result = "FAIL"
		res.Note = "post-restore: " + err.Error()
		fmt.Fprintf(os.Stderr, "  FAIL %s/%s: post-restore: %v\n", r.File, g.Name, err)
		return
	}

	res.Result = "PASS"
	fmt.Fprintf(os.Stderr, "  PASS %s/%s\n", r.File, g.Name)
}

// mutate dispatches to the correct rewrite strategy for g.Kind.
// Returns the original bytes so the caller can restore.
func mutate(path string, g Gate) ([]byte, error) {
	switch g.Kind {
	case GateBoolConst:
		return FlipBoolConstFalse(path, g.Name)
	case GateStringMutation:
		return ReplaceString(path, g.MutationFrom, g.MutationTo)
	default:
		return nil, fmt.Errorf("unsupported gate kind %q", g.Kind)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test shell-out
// ─────────────────────────────────────────────────────────────────────

type testOutcome int

const (
	wantPass testOutcome = iota
	wantFail
)

// runTests shells out to `go test -run '^(A|B|C)$' <pkg> -count=1`
// and asserts the outcome matches want. Returns nil on match, an
// explanatory error on mismatch.
func runTests(pkg string, testNames []string, want testOutcome) error {
	runArg := "^(" + strings.Join(testNames, "|") + ")$"
	cmd := exec.Command("go", "test", "-run", runArg, pkg, "-count=1", "-timeout=120s")
	cmd.Env = append(os.Environ(), "GOFLAGS=") // ignore user -race etc to keep predictable
	out, err := cmd.CombinedOutput()

	passed := err == nil
	switch want {
	case wantPass:
		if !passed {
			return fmt.Errorf("expected tests to pass but they failed:\n%s", string(out))
		}
		return nil
	case wantFail:
		if passed {
			return fmt.Errorf("expected tests to fail but all passed:\n%s", string(out))
		}
		return nil
	default:
		return fmt.Errorf("unknown want %v", want)
	}
}
