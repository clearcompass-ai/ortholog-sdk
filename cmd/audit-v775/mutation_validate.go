// cmd/audit-v775/mutation_validate.go — the --validate-registries
// pass. Split out of mutation.go to keep each file under the
// 300-line budget. Every registry must pass these checks or the
// runner exits 3; the CI guard at scripts/verify-phase-c-decomm.sh
// calls this via `make audit-v775`.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// runValidateRegistries checks every registry for source and test
// drift without running any tests. Exits with code 3 on drift,
// code 0 on clean.
func runValidateRegistries(regs []*Registry) {
	var drift []string

	// Cache source bytes per-file to avoid redundant I/O when a
	// registry's gates cover more than one file via source_file.
	srcCache := map[string]string{}
	readSource := func(path string) (string, error) {
		if s, ok := srcCache[path]; ok {
			return s, nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		s := string(b)
		srcCache[path] = s
		return s, nil
	}

	for _, r := range regs {
		// 1. The registry-level source file must exist.
		if _, err := os.Stat(r.File); err != nil {
			drift = append(drift, fmt.Sprintf(
				"%s: source file %q does not exist",
				r.RegistryPath, r.File))
			continue
		}
		for _, g := range r.Gates {
			src := g.ResolveSourceFile(r.File)
			// 2a. Every gate's source file (possibly overridden) must exist.
			if _, err := os.Stat(src); err != nil {
				drift = append(drift, fmt.Sprintf(
					"%s: gate %q: source_file %q does not exist",
					r.RegistryPath, g.Name, src))
				continue
			}
			srcText, err := readSource(src)
			if err != nil {
				drift = append(drift, fmt.Sprintf(
					"%s: gate %q: read source %q: %v",
					r.RegistryPath, g.Name, src, err))
				continue
			}
			// 2b. Per-gate source check.
			switch g.Kind {
			case GateBoolConst:
				re := findBoolConstLineRE(g.Name)
				if !re.MatchString(srcText) {
					drift = append(drift, fmt.Sprintf(
						"%s: gate %q: no `%s = true` declaration in %s",
						r.RegistryPath, g.Name, g.Name, src))
				}
			case GateStringMutation:
				if !strings.Contains(srcText, g.MutationFrom) {
					drift = append(drift, fmt.Sprintf(
						"%s: gate %q: mutation_from %q absent from %s",
						r.RegistryPath, g.Name, g.MutationFrom, src))
				}
			}
			// 3. Every declared test must exist in the package.
			missing := missingTestsInPackage(r.Package, g.Tests)
			for _, t := range missing {
				drift = append(drift, fmt.Sprintf(
					"%s: gate %q: binding test %s not found in package %s",
					r.RegistryPath, g.Name, t, r.Package))
			}
		}
	}

	if len(drift) > 0 {
		fmt.Fprintln(os.Stderr, "audit-v775: registry drift detected:")
		for _, d := range drift {
			fmt.Fprintf(os.Stderr, "  %s\n", d)
		}
		os.Exit(3)
	}
	fmt.Fprintf(os.Stderr, "audit-v775: %d registries validated clean\n", len(regs))
}

// missingTestsInPackage returns names in want that are NOT found as
// `func TestFoo(t *testing.T)` in any file of pkg. Uses `go test
// -list .*` to enumerate test functions without running them.
func missingTestsInPackage(pkg string, want []string) []string {
	cmd := exec.Command("go", "test", "-list", ".*", pkg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// If the package fails to load, surface every requested test
		// as missing — the operator needs to see the failure and fix
		// the source.
		return append([]string(nil), want...)
	}
	present := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Test") {
			present[line] = true
		}
	}
	var missing []string
	for _, t := range want {
		if !present[t] {
			missing = append(missing, t)
		}
	}
	return missing
}
