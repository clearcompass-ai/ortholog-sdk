package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTempRegistry writes yaml content under a temp dir and
// returns the absolute path. The file is cleaned up automatically.
func writeTempRegistry(t *testing.T, yaml string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "x.mutation-audit.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestLoadRegistry_HappyPath(t *testing.T) {
	path := writeTempRegistry(t, `
file: crypto/artifact/pre.go
package: github.com/example/pkg
gates:
  - name: muEnableFoo
    kind: bool_const
    description: test
    tests:
      - TestFoo
`)
	r, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if r.File != "crypto/artifact/pre.go" {
		t.Fatalf("file drift: %q", r.File)
	}
	if len(r.Gates) != 1 || r.Gates[0].Name != "muEnableFoo" {
		t.Fatalf("gate drift: %+v", r.Gates)
	}
	if r.Gates[0].Kind != GateBoolConst {
		t.Fatalf("kind drift: %q", r.Gates[0].Kind)
	}
}

func TestLoadRegistry_RejectsDuplicateGateNames(t *testing.T) {
	path := writeTempRegistry(t, `
file: pkg/file.go
package: github.com/example/pkg
gates:
  - name: muX
    kind: bool_const
    description: a
    tests: [TestA]
  - name: muX
    kind: bool_const
    description: b
    tests: [TestB]
`)
	_, err := LoadRegistry(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate gate") {
		t.Fatalf("want duplicate-gate error, got %v", err)
	}
}

func TestLoadRegistry_RejectsUnknownKind(t *testing.T) {
	path := writeTempRegistry(t, `
file: x.go
package: github.com/example/pkg
gates:
  - name: muX
    kind: badkind
    description: x
    tests: [TestX]
`)
	_, err := LoadRegistry(path)
	if err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Fatalf("want unknown-kind error, got %v", err)
	}
}

func TestLoadRegistry_RejectsMissingTests(t *testing.T) {
	path := writeTempRegistry(t, `
file: x.go
package: github.com/example/pkg
gates:
  - name: muX
    kind: bool_const
    description: x
`)
	_, err := LoadRegistry(path)
	if err == nil || !strings.Contains(err.Error(), "no binding tests") {
		t.Fatalf("want no-tests error, got %v", err)
	}
}

func TestLoadRegistry_RejectsBadGateIdent(t *testing.T) {
	path := writeTempRegistry(t, `
file: x.go
package: github.com/example/pkg
gates:
  - name: "not an ident"
    kind: bool_const
    description: x
    tests: [TestX]
`)
	_, err := LoadRegistry(path)
	if err == nil || !strings.Contains(err.Error(), "valid Go identifier") {
		t.Fatalf("want bad-ident error, got %v", err)
	}
}

func TestLoadRegistry_StringMutationRequiresFromTo(t *testing.T) {
	path := writeTempRegistry(t, `
file: x.go
package: github.com/example/pkg
gates:
  - name: Flip
    kind: string_mutation
    description: x
    tests: [TestX]
`)
	_, err := LoadRegistry(path)
	if err == nil || !strings.Contains(err.Error(), "mutation_from") {
		t.Fatalf("want mutation_from error, got %v", err)
	}
}

func TestLoadRegistry_StringMutationRejectsIdenticalFromTo(t *testing.T) {
	path := writeTempRegistry(t, `
file: x.go
package: github.com/example/pkg
gates:
  - name: Flip
    kind: string_mutation
    description: x
    mutation_from: SAME
    mutation_to:   SAME
    tests: [TestX]
`)
	_, err := LoadRegistry(path)
	if err == nil || !strings.Contains(err.Error(), "identical") {
		t.Fatalf("want identical error, got %v", err)
	}
}

func TestLoadRegistry_RejectsNonTestFunction(t *testing.T) {
	path := writeTempRegistry(t, `
file: x.go
package: github.com/example/pkg
gates:
  - name: muX
    kind: bool_const
    description: x
    tests: [NotATestFunction]
`)
	_, err := LoadRegistry(path)
	if err == nil || !strings.Contains(err.Error(), "does not start with Test") {
		t.Fatalf("want Test-prefix error, got %v", err)
	}
}

func TestGate_ResolveSourceFile_OverridesRegistryFile(t *testing.T) {
	g := Gate{Name: "muX", Kind: GateBoolConst, SourceFile: "other/file.go"}
	if got := g.ResolveSourceFile("pkg/registry_file.go"); got != "other/file.go" {
		t.Fatalf("SourceFile override lost: %q", got)
	}
}

func TestGate_ResolveSourceFile_FallsBackToRegistryFile(t *testing.T) {
	g := Gate{Name: "muX", Kind: GateBoolConst} // no SourceFile
	if got := g.ResolveSourceFile("pkg/file.go"); got != "pkg/file.go" {
		t.Fatalf("fallback broken: %q", got)
	}
}

func TestLoadRegistry_AcceptsPerGateSourceFile(t *testing.T) {
	path := writeTempRegistry(t, `
file: pkg/primary.go
package: github.com/example/pkg
gates:
  - name: Flip
    kind: string_mutation
    source_file: pkg/sibling.go
    description: x
    mutation_from: FOO
    mutation_to:   BAR
    tests: [TestX]
`)
	r, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if r.Gates[0].SourceFile != "pkg/sibling.go" {
		t.Fatalf("source_file not parsed: %+v", r.Gates[0])
	}
	if got := r.Gates[0].ResolveSourceFile(r.File); got != "pkg/sibling.go" {
		t.Fatalf("ResolveSourceFile should prefer per-gate override, got %q", got)
	}
}

func TestLoadRegistry_RejectsEmpty(t *testing.T) {
	path := writeTempRegistry(t, `
file: x.go
package: github.com/example/pkg
gates: []
`)
	_, err := LoadRegistry(path)
	if err == nil || !strings.Contains(err.Error(), "zero gates") {
		t.Fatalf("want zero-gates error, got %v", err)
	}
}

func TestLoadRegistry_RejectsMissingFile(t *testing.T) {
	path := writeTempRegistry(t, `
package: github.com/example/pkg
gates:
  - name: muX
    kind: bool_const
    description: x
    tests: [TestX]
`)
	_, err := LoadRegistry(path)
	if err == nil || !strings.Contains(err.Error(), "empty file") {
		t.Fatalf("want empty-file error, got %v", err)
	}
}

func TestFindRegistries_DiscoversRepoRegistries(t *testing.T) {
	// Run from repo root (two levels up from cmd/audit-v775).
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	if err := os.Chdir(filepath.Join("..", "..")); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	paths, err := FindRegistries(".")
	if err != nil {
		t.Fatalf("FindRegistries: %v", err)
	}
	// Every registry path ends in .mutation-audit.yaml.
	for _, p := range paths {
		if !strings.HasSuffix(p, ".mutation-audit.yaml") {
			t.Fatalf("non-registry path surfaced: %s", p)
		}
	}
	// We expect at least the four canonical registries.
	wantAtLeast := []string{
		"crypto/artifact/pre.mutation-audit.yaml",
		"crypto/escrow/split_commitment.mutation-audit.yaml",
		"core/vss/transcript.mutation-audit.yaml",
		"lifecycle/commitment_atomic.mutation-audit.yaml",
	}
	for _, want := range wantAtLeast {
		found := false
		for _, got := range paths {
			if strings.HasSuffix(got, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected registry %q not discovered in %v", want, paths)
		}
	}
}

func TestFindRegistries_SkipsVendorAndGit(t *testing.T) {
	dir := t.TempDir()
	// Registry outside vendor.
	os.WriteFile(filepath.Join(dir, "live.mutation-audit.yaml"), []byte(""), 0644)
	// Registry inside vendor (should be skipped).
	vendorDir := filepath.Join(dir, "vendor", "sub")
	os.MkdirAll(vendorDir, 0755)
	os.WriteFile(filepath.Join(vendorDir, "vendored.mutation-audit.yaml"), []byte(""), 0644)
	// Registry inside .git (should be skipped).
	gitDir := filepath.Join(dir, ".git", "sub")
	os.MkdirAll(gitDir, 0755)
	os.WriteFile(filepath.Join(gitDir, "git.mutation-audit.yaml"), []byte(""), 0644)

	paths, err := FindRegistries(dir)
	if err != nil {
		t.Fatalf("FindRegistries: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 live registry, got %d: %v", len(paths), paths)
	}
	if !strings.HasSuffix(paths[0], "live.mutation-audit.yaml") {
		t.Fatalf("wrong registry returned: %s", paths[0])
	}
}
