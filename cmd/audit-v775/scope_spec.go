// cmd/audit-v775/scope_spec.go — v7.75 "Provenance" scope
// specification plus the symbol-index helpers that translate the
// spec into an AST matcher. Split out of scope.go to keep each
// file under the 300-line budget.
package main

import (
	"fmt"
	"strings"

	"golang.org/x/tools/go/packages"
)

// ─────────────────────────────────────────────────────────────────────
// SPEC — v7.75 Provenance scope specification
// ─────────────────────────────────────────────────────────────────────
//
// Every file that references any symbol below is in v7.75's review
// surface. Inclusion does not mean "must change" — it means "must
// be read and triaged." Files with only unchanged-behavior
// references are explicitly annotated as such in the audit output.

// changedPackages are packages whose exported surface changes in v7.75.
var changedPackages = []packageSpec{
	{Path: "github.com/clearcompass-ai/ortholog-sdk/core/vss", Kind: "new"},
	{Path: "github.com/clearcompass-ai/ortholog-sdk/crypto/artifact", Kind: "modified"},
	{Path: "github.com/clearcompass-ai/ortholog-sdk/crypto/escrow", Kind: "modified"},
	{Path: "github.com/clearcompass-ai/ortholog-sdk/exchange/identity", Kind: "modified"},
	{Path: "github.com/clearcompass-ai/ortholog-sdk/schema", Kind: "modified"},
	{Path: "github.com/clearcompass-ai/ortholog-sdk/lifecycle", Kind: "modified"},
	{Path: "github.com/clearcompass-ai/ortholog-sdk/builder", Kind: "modified-partial"},
}

// changedSymbols are exported identifiers whose signature, shape,
// or contract changes in v7.75.
var changedSymbols = []symbolSpec{
	{Pkg: "crypto/artifact", Name: "CFrag", Reason: "gains BKX/BKY fields per CD3"},
	{Pkg: "crypto/artifact", Name: "KFrag", Reason: "generation takes Pedersen blinding polynomial"},
	{Pkg: "crypto/artifact", Name: "PRE_GenerateKFrags", Reason: "signature extends per CD3"},
	{Pkg: "crypto/artifact", Name: "PRE_VerifyCFrag", Reason: "adds Pedersen verification step"},
	{Pkg: "crypto/artifact", Name: "PRE_Encrypt", Reason: "re-read: composition with Pedersen binding"},
	{Pkg: "crypto/artifact", Name: "PRE_DecryptFrags", Reason: "re-read: consumes new CFrag shape"},
	{Pkg: "crypto/escrow", Name: "Share", Reason: "V2 fields populated by default post-v7.75"},
	{Pkg: "crypto/escrow", Name: "ValidateShareFormat", Reason: "accepts V2"},
	{Pkg: "crypto/escrow", Name: "SerializeShare", Reason: "re-read: V2 field interpretation"},
	{Pkg: "crypto/escrow", Name: "DeserializeShare", Reason: "re-read: V2 field interpretation"},
	{Pkg: "crypto/escrow", Name: "VersionV1", Reason: "legacy read-only post-v7.75"},
	{Pkg: "crypto/escrow", Name: "VersionV2", Reason: "becomes active"},
	{Pkg: "exchange/identity", Name: "*", Reason: "mapping_escrow uses V2 + commitment entries"},
	{Pkg: "schema", Name: "JSONParameterExtractor", Reason: "recognizes commitment schema"},
	{Pkg: "schema", Name: "MarshalParameters", Reason: "re-read: confirm no interaction"},
	{Pkg: "lifecycle", Name: "Recover", Reason: "fetches and verifies commitments"},
	{Pkg: "lifecycle", Name: "Provision", Reason: "emits commitment entry at split time"},
	{Pkg: "lifecycle", Name: "RotateDelegationKey", Reason: "emits commitment on re-split"},
	{Pkg: "builder", Name: "BuildEscrowSplitCommitment", Reason: "new (v7.75)"},
}

// ─────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────

type packageSpec struct {
	Path string
	Kind string
}

type symbolSpec struct {
	Pkg    string
	Name   string
	Reason string
}

type evidence struct {
	File        string   `json:"file"`
	IsTest      bool     `json:"is_test"`
	Symbols     []string `json:"symbols"`
	Imports     []string `json:"imports"`
	Kind        string   `json:"kind"`
	Disposition string   `json:"disposition"`
	Rationale   []string `json:"rationale"`
}

// ─────────────────────────────────────────────────────────────────────
// Spec validation + symbol index
// ─────────────────────────────────────────────────────────────────────

func validateSpec(pkgs []*packages.Package) error {
	byShort := map[string]*packages.Package{}
	for _, p := range pkgs {
		byShort[shortPath(p.PkgPath)] = p
	}
	var missing []string
	for _, s := range changedSymbols {
		p, ok := byShort[s.Pkg]
		if !ok {
			missing = append(missing, fmt.Sprintf("package %q not found", s.Pkg))
			continue
		}
		if s.Name == "*" {
			continue
		}
		if p.Types == nil || p.Types.Scope() == nil {
			missing = append(missing, fmt.Sprintf("package %q has no type scope", s.Pkg))
			continue
		}
		if p.Types.Scope().Lookup(s.Name) == nil {
			missing = append(missing,
				fmt.Sprintf("symbol %s.%s not found in loaded tree", s.Pkg, s.Name))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("spec references missing symbols:\n  %s",
			strings.Join(missing, "\n  "))
	}
	return nil
}

type symbolIndex struct {
	exact    map[string]string
	wildcard map[string]string
}

func buildSymbolIndex(specs []symbolSpec) *symbolIndex {
	idx := &symbolIndex{
		exact:    map[string]string{},
		wildcard: map[string]string{},
	}
	for _, s := range specs {
		if s.Name == "*" {
			idx.wildcard[s.Pkg] = s.Reason
		} else {
			idx.exact[s.Pkg+"."+s.Name] = s.Reason
		}
	}
	return idx
}

func (i *symbolIndex) match(pkg, name string) (bool, string) {
	if reason, ok := i.exact[pkg+"."+name]; ok {
		return true, reason
	}
	if reason, ok := i.wildcard[pkg]; ok {
		return true, reason
	}
	return false, ""
}
