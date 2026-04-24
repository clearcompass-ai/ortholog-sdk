// cmd/audit-v775/registry.go — mutation-audit registry loader.
//
// Reads *.mutation-audit.yaml files from anywhere in the repo,
// parses them into a canonical in-memory representation, and
// validates the declared gates against the source files and test
// symbols they reference.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// GateKind is the mutation strategy for a gate.
type GateKind string

const (
	// GateBoolConst flips a `muEnableFoo = true` line to `false`.
	// The gate name MUST match the constant identifier.
	GateBoolConst GateKind = "bool_const"

	// GateStringMutation replaces every occurrence of
	// MutationFrom with MutationTo file-wide. Used for DST
	// string pins where there is no boolean constant to flip.
	GateStringMutation GateKind = "string_mutation"
)

// Gate describes a single mutation probe in a registry.
type Gate struct {
	Name          string   `yaml:"name"`
	Kind          GateKind `yaml:"kind"`
	Description   string   `yaml:"description"`
	Tests         []string `yaml:"tests"`
	MutationFrom  string   `yaml:"mutation_from,omitempty"`
	MutationTo    string   `yaml:"mutation_to,omitempty"`
}

// Registry is the parsed contents of one *.mutation-audit.yaml file.
type Registry struct {
	// RegistryPath is the filesystem path to the YAML file itself
	// (relative to repo root). Populated by LoadRegistry.
	RegistryPath string `yaml:"-"`

	// File is the repo-relative path to the source file the
	// registry mutates.
	File string `yaml:"file"`

	// Package is the Go import path of the package holding File.
	// Used by the runner to scope `go test` invocations.
	Package string `yaml:"package"`

	// Gates is the set of mutation probes for this file.
	Gates []Gate `yaml:"gates"`
}

// ─────────────────────────────────────────────────────────────────────
// Discovery
// ─────────────────────────────────────────────────────────────────────

// FindRegistries walks the repo tree from root and returns every
// *.mutation-audit.yaml file it finds, skipping vendor/ and
// .git/ subtrees.
func FindRegistries(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".mutation-audit.yaml") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────
// Loading
// ─────────────────────────────────────────────────────────────────────

// LoadRegistry reads and parses a single registry file.
func LoadRegistry(path string) (*Registry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var r Registry
	if err := yaml.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	r.RegistryPath = path
	if err := r.staticCheck(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &r, nil
}

// LoadAllRegistries discovers every registry under root and parses
// each in turn. Returns the registries in stable sorted order.
func LoadAllRegistries(root string) ([]*Registry, error) {
	paths, err := FindRegistries(root)
	if err != nil {
		return nil, err
	}
	out := make([]*Registry, 0, len(paths))
	for _, p := range paths {
		r, err := LoadRegistry(p)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// staticCheck validates the structural invariants of a loaded
// registry without touching the filesystem or running tests.
func (r *Registry) staticCheck() error {
	if r.File == "" {
		return fmt.Errorf("empty file field")
	}
	if r.Package == "" {
		return fmt.Errorf("empty package field")
	}
	if len(r.Gates) == 0 {
		return fmt.Errorf("registry has zero gates")
	}
	seen := map[string]struct{}{}
	for i, g := range r.Gates {
		if g.Name == "" {
			return fmt.Errorf("gate[%d] has empty name", i)
		}
		if _, dup := seen[g.Name]; dup {
			return fmt.Errorf("duplicate gate name %q", g.Name)
		}
		seen[g.Name] = struct{}{}
		switch g.Kind {
		case GateBoolConst:
			if !goIdentRE.MatchString(g.Name) {
				return fmt.Errorf("gate %q: bool_const name is not a valid Go identifier", g.Name)
			}
		case GateStringMutation:
			if g.MutationFrom == "" || g.MutationTo == "" {
				return fmt.Errorf("gate %q: string_mutation requires mutation_from and mutation_to", g.Name)
			}
			if g.MutationFrom == g.MutationTo {
				return fmt.Errorf("gate %q: mutation_from and mutation_to are identical", g.Name)
			}
		case "":
			return fmt.Errorf("gate %q: kind missing", g.Name)
		default:
			return fmt.Errorf("gate %q: unknown kind %q", g.Name, g.Kind)
		}
		if len(g.Tests) == 0 {
			return fmt.Errorf("gate %q: no binding tests declared", g.Name)
		}
		for _, tn := range g.Tests {
			if !strings.HasPrefix(tn, "Test") {
				return fmt.Errorf("gate %q: test %q does not start with Test", g.Name, tn)
			}
		}
	}
	return nil
}

// goIdentRE matches valid Go identifiers.
var goIdentRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
