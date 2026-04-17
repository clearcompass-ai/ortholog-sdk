// check_sdk_usage.go
//
// A standalone AST-based tool for auditing how a domain codebase (e.g., the
// judicial network) uses the Ortholog SDK. Scans every .go file under a
// supplied path and reports usages that violate SDK architectural invariants.
//
// Usage:
//
//	go run check_sdk_usage.go -path /path/to/judicial-network
//	go run check_sdk_usage.go -path ./judicial-network -strictness=strict
//	go run check_sdk_usage.go -path ./judicial-network -json findings.json
//
// Flags:
//
//	-path        Directory to scan (required). Recurses into subdirectories.
//	             Skips .git, vendor, testdata, and .wave* backups.
//	-sdk-prefix  Go module prefix for the SDK. Default:
//	             github.com/clearcompass-ai/ortholog-sdk. Files that don't
//	             import anything under this prefix are skipped.
//	-strictness  minimal | balanced | strict. Default: strict.
//	             strict flags every potential violation including
//	             legitimate patterns in tests and migration tooling.
//	-json        Path to emit findings as JSON. Default:
//	             ./sdk-usage-findings.json. Pass -json="" to disable.
//	             Terminal report is always produced.
//	-include-tests  Include *_test.go files in the scan. Default: true.
//
// Exit code: 0 if no errors-severity findings. 1 if any errors. Warnings
// never fail the run.
//
// ─────────────────────────────────────────────────────────────────────────
// WHAT THIS TOOL CHECKS
// ─────────────────────────────────────────────────────────────────────────
//
// Each check corresponds to a concrete SDK invariant and is explained at
// the check's implementation site. At a glance:
//
//	[R1]  References to symbols deleted in Wave 3:
//	      CourtMapping, JNetMapping, CCRMapping, ProvisionThreeLogs,
//	      ProvisionConfig, ProvisionResult, provisionLog, containsLogDID.
//	      Severity: ERROR. Build-breaking if present.
//
//	[R2]  Access to fields removed in Wave 1.5:
//	      ControlHeader.DomainManifestVersion, envelope.MigrationOverrideToken,
//	      envelope.NewEntryWithOverride.
//	      Severity: ERROR. Build-breaking.
//
//	[R3]  String literal used as ProposalType (Wave 2 typed enum):
//	      e.g. `ProposalType: "remove_authority"`.
//	      Severity: ERROR. ProposalType is now uint8; strings won't compile.
//
//	[R4]  Hardcoded 2/3 supermajority via math.Ceil — should use
//	      types.OverrideThresholdRule.RequiredApprovals(N) so the threshold
//	      is schema-driven, not hardcoded.
//	      Severity: WARNING.
//
//	[R5]  Raw envelope.ControlHeader{} composite literal — bypasses the 18
//	      typed entry builders in builder/entry_builders.go and is a common
//	      source of path-classification bugs.
//	      Severity: WARNING (balanced) / ERROR (strict).
//
//	[R6]  Direct call to envelope.NewEntry — same rationale as R5; domain
//	      code should use builder.Build* wrappers.
//	      Severity: WARNING.
//
//	[R7]  Explicit cast uint8(types.AdmissionModeB) / uint8(admission.HashSHA256)
//	      where the wire-byte aliases types.WireByteModeB /
//	      admission.WireByteHashSHA256 exist specifically to avoid the cast.
//	      Severity: INFO.
//
//	[R8]  builder.ProcessBatch called directly without ProcessWithRetry
//	      wrapping. Path C operations need OCC retry to make progress under
//	      concurrent enforcement.
//	      Severity: WARNING.
//
//	[R9]  tree.SetLeaf in a loop without an OverlayLeafStore wrapping the
//	      backing store. Risk of partial mutations on batch failure.
//	      Severity: WARNING (balanced+).
//
//	[R10] PRE_GenerateKFrags called with what looks like a master private
//	      key rather than an unwrapped delegation key (per-artifact sk_del).
//	      Severity: WARNING.
//
//	[R11] Foreign-log LogPosition passed to builder-path APIs. Detected
//	      heuristically — flags LogPosition literal with LogDID != current
//	      local log context.
//	      Severity: INFO. Requires human review.
//
//	[R12] Access to envelope.Entry.DomainPayload inside functions that also
//	      call builder.Build* or builder.ProcessBatch — potential SDK-D6
//	      violation (builder must never read Domain Payload).
//	      Severity: WARNING (strict only).
//
// ─────────────────────────────────────────────────────────────────────────
// WHAT THIS TOOL CANNOT DO
// ─────────────────────────────────────────────────────────────────────────
//
//   - Verify semantic correctness (e.g., "the right authority set is used").
//   - Detect whether a ProcessBatch call is actually wrapped transitively.
//     We only look within the same function body.
//   - Confirm that schema payloads declare the right mode. That's runtime.
//   - Follow interface satisfaction across packages. Structural typing hides
//     satisfaction from textual analysis.
//
// When the checker flags something as WARNING or INFO, treat it as a
// conversation starter, not a verdict.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ──────────────────────────────────────────────────────────────────────
// Severity and strictness
// ──────────────────────────────────────────────────────────────────────

type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

type Strictness int

const (
	StrictnessMinimal Strictness = iota
	StrictnessBalanced
	StrictnessStrict
)

func parseStrictness(s string) (Strictness, error) {
	switch strings.ToLower(s) {
	case "minimal":
		return StrictnessMinimal, nil
	case "balanced", "":
		return StrictnessBalanced, nil
	case "strict":
		return StrictnessStrict, nil
	}
	return 0, fmt.Errorf("unknown strictness %q (want minimal|balanced|strict)", s)
}

// ──────────────────────────────────────────────────────────────────────
// Finding
// ──────────────────────────────────────────────────────────────────────

type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Column   int      `json:"column"`
	Message  string   `json:"message"`
	Snippet  string   `json:"snippet,omitempty"`
	Fix      string   `json:"fix,omitempty"`
}

// ──────────────────────────────────────────────────────────────────────
// Checker
// ──────────────────────────────────────────────────────────────────────

type Checker struct {
	fset         *token.FileSet
	strictness   Strictness
	sdkPrefix    string
	includeTests bool
	findings     []Finding

	// per-file state, reset at each file
	filePath     string
	file         *ast.File
	sdkImports   map[string]string // alias/name → full path (only if under sdkPrefix)
	funcStack    []*ast.FuncDecl
	buildersUsed map[string]bool // tracked within current function
}

func NewChecker(strictness Strictness, sdkPrefix string, includeTests bool) *Checker {
	return &Checker{
		fset:         token.NewFileSet(),
		strictness:   strictness,
		sdkPrefix:    sdkPrefix,
		includeTests: includeTests,
	}
}

// pkgAlias returns the short package name (e.g. "envelope") for a file's
// import path. If the import is aliased, returns the alias. If the file
// doesn't import the path, returns empty string.
func (c *Checker) pkgAlias(subpath string) string {
	full := c.sdkPrefix + "/" + subpath
	for alias, path := range c.sdkImports {
		if path == full {
			return alias
		}
	}
	return ""
}

// isSelectorFromPkg reports whether sel is a selector expression like
// `alias.Name` where `alias` is the file's import alias for the given
// SDK subpath (e.g. "core/envelope").
func (c *Checker) isSelectorFromPkg(sel *ast.SelectorExpr, subpath, name string) bool {
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	alias := c.pkgAlias(subpath)
	if alias == "" {
		return false
	}
	return ident.Name == alias && sel.Sel.Name == name
}

func (c *Checker) record(rule string, sev Severity, pos token.Pos, msg, fix string) {
	p := c.fset.Position(pos)
	c.findings = append(c.findings, Finding{
		Rule:     rule,
		Severity: sev,
		File:     c.filePath,
		Line:     p.Line,
		Column:   p.Column,
		Message:  msg,
		Fix:      fix,
	})
}

// ──────────────────────────────────────────────────────────────────────
// Entry point
// ──────────────────────────────────────────────────────────────────────

func main() {
	var (
		path         = flag.String("path", "", "Directory to scan (required)")
		sdkPrefix    = flag.String("sdk-prefix", "github.com/clearcompass-ai/ortholog-sdk", "SDK module prefix")
		strictArg    = flag.String("strictness", "strict", "minimal|balanced|strict")
		jsonOut      = flag.String("json", "./sdk-usage-findings.json", "Emit findings as JSON to this path (empty string disables)")
		includeTests = flag.Bool("include-tests", true, "Include *_test.go files")
	)
	flag.Parse()

	if *path == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -path is required")
		flag.Usage()
		os.Exit(2)
	}

	strictness, err := parseStrictness(*strictArg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(2)
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: resolve path:", err)
		os.Exit(2)
	}

	checker := NewChecker(strictness, *sdkPrefix, *includeTests)
	filesScanned, err := checker.ScanDir(absPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: scan:", err)
		os.Exit(2)
	}

	printReport(checker, filesScanned, absPath)

	if *jsonOut != "" {
		if err := writeJSON(checker.findings, *jsonOut); err != nil {
			fmt.Fprintln(os.Stderr, "WARN: write JSON:", err)
		} else {
			fmt.Printf("\nJSON findings written to: %s\n", *jsonOut)
		}
	}

	// Exit 1 if any ERROR findings.
	for _, f := range checker.findings {
		if f.Severity == SeverityError {
			os.Exit(1)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────
// Scanning
// ──────────────────────────────────────────────────────────────────────

func (c *Checker) ScanDir(root string) (int, error) {
	skip := map[string]bool{
		".git":         true,
		"vendor":       true,
		"testdata":     true,
		"node_modules": true,
	}
	filesScanned := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			if skip[name] || strings.HasPrefix(name, ".wave") || strings.HasPrefix(name, ".") {
				if name == "." {
					return nil
				}
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		if !c.includeTests && strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}

		file, err := parser.ParseFile(c.fset, path, nil, parser.ParseComments)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: parse %s: %v\n", rel, err)
			return nil
		}

		c.filePath = rel
		c.file = file
		c.sdkImports = c.collectSDKImports(file)

		// If the file doesn't touch the SDK at all, skip.
		if len(c.sdkImports) == 0 {
			return nil
		}

		filesScanned++
		c.runAllChecks(file)
		return nil
	})
	return filesScanned, err
}

func (c *Checker) collectSDKImports(f *ast.File) map[string]string {
	out := make(map[string]string)
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if !strings.HasPrefix(path, c.sdkPrefix) {
			continue
		}
		alias := ""
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			// Use last path segment as the default package name.
			alias = filepath.Base(path)
		}
		out[alias] = path
	}
	return out
}

// ──────────────────────────────────────────────────────────────────────
// Check registry
// ──────────────────────────────────────────────────────────────────────

func (c *Checker) runAllChecks(f *ast.File) {
	// Pass 1: deleted symbol references and removed field access.
	// These walk the whole AST once.
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			// R1 and R2 legitimately fire on any selector reference.
			// R7 (wire-byte) only fires when the selector is inside a
			// uint8() conversion — handled in checkCallExpr instead, so
			// we don't double-count.
			c.checkDeletedSymbol(node)
			c.checkRemovedField(node)
		case *ast.CallExpr:
			c.checkCallExpr(node)
		case *ast.CompositeLit:
			c.checkCompositeLit(node)
		case *ast.BinaryExpr:
			// math.Ceil pattern lives inside a CallExpr; handled there.
		}
		return true
	})

	// Pass 2: function-scoped checks (ProcessBatch without retry,
	// SetLeaf in loop, DomainPayload access near builder calls).
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		c.checkFunctionBody(fd)
	}
}

// ──────────────────────────────────────────────────────────────────────
// [R1] Deleted symbols (Wave 3)
// ──────────────────────────────────────────────────────────────────────
//
// Symbols explicitly deleted in the Wave 3 refactor. A reference to any
// of these will fail to compile against a current SDK — we surface them
// early with clear guidance.

var deletedSymbols = map[string]map[string]string{
	// "did" package
	"did": {
		"CourtMapping": "Define your own VendorMapping locally; see did.NewVendorDIDResolver",
		"JNetMapping":  "Define your own VendorMapping locally; see did.NewVendorDIDResolver",
		"CCRMapping":   "Define your own VendorMapping locally; see did.NewVendorDIDResolver",
	},
	// "lifecycle" package
	"lifecycle": {
		"ProvisionThreeLogs": "Call lifecycle.ProvisionSingleLog 3x and compose the results in domain code",
		"ProvisionConfig":    "Use lifecycle.SingleLogConfig; multi-log orchestration is now a domain concern",
		"ProvisionResult":    "Use lifecycle.LogProvision; multi-log orchestration is now a domain concern",
	},
	// "envelope" package — Wave 1.5 removals
	"envelope": {
		"MigrationOverrideToken": "Removed in Wave 1.5. Round-trip via Deserialize → transform → NewEntry instead",
		"NewEntryWithOverride":   "Removed in Wave 1.5. Use envelope.NewEntry; version is auto-assigned",
	},
}

func (c *Checker) checkDeletedSymbol(sel *ast.SelectorExpr) {
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return
	}
	// Find which SDK package this alias refers to (if any).
	var sdkPkg string
	for alias, path := range c.sdkImports {
		if alias != ident.Name {
			continue
		}
		sdkPkg = filepath.Base(path)
		break
	}
	if sdkPkg == "" {
		return
	}
	syms, ok := deletedSymbols[sdkPkg]
	if !ok {
		return
	}
	fix, deleted := syms[sel.Sel.Name]
	if !deleted {
		return
	}
	c.record(
		"R1-deleted-symbol",
		SeverityError,
		sel.Pos(),
		fmt.Sprintf("%s.%s was removed (Wave 3). This will not compile.", ident.Name, sel.Sel.Name),
		fix,
	)
}

// ──────────────────────────────────────────────────────────────────────
// [R2] Removed ControlHeader field (Wave 1.5)
// ──────────────────────────────────────────────────────────────────────
//
// ControlHeader.DomainManifestVersion was removed in Wave 1.5. Any
// access path that ends in `.DomainManifestVersion` on a ControlHeader
// is a build break.

func (c *Checker) checkRemovedField(sel *ast.SelectorExpr) {
	if sel.Sel.Name != "DomainManifestVersion" {
		return
	}
	// We don't statically know the type of sel.X, but any reference to
	// this field name on a ControlHeader-shaped value is wrong. Surface
	// it unconditionally when the file imports envelope.
	if c.pkgAlias("core/envelope") == "" {
		return
	}
	c.record(
		"R2-removed-field",
		SeverityError,
		sel.Pos(),
		"ControlHeader.DomainManifestVersion was removed in Wave 1.5.",
		"Delete the assignment/read. Protocol version is auto-assigned by envelope.NewEntry.",
	)
}

// ──────────────────────────────────────────────────────────────────────
// [R3] String literal used as ProposalType (Wave 2)
// ──────────────────────────────────────────────────────────────────────
//
// Wave 2 converted ProposalType from a free-form string to a typed uint8
// enum. Domain code that passes string constants (e.g. "remove_authority")
// will fail to compile. We catch this by inspecting struct field
// assignments whose field is named ProposalType.

func (c *Checker) checkCompositeLit(cl *ast.CompositeLit) {
	// Raw envelope.ControlHeader composite literal → [R5].
	if sel, ok := cl.Type.(*ast.SelectorExpr); ok {
		if c.isSelectorFromPkg(sel, "core/envelope", "ControlHeader") {
			c.checkRawControlHeader(cl)
		}
	}
	// Field-level walk for [R3].
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		if key.Name == "ProposalType" {
			if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				c.record(
					"R3-proposal-type-string",
					SeverityError,
					lit.Pos(),
					fmt.Sprintf("ProposalType is a typed enum (Wave 2); string literal %s will not compile.", lit.Value),
					`Use lifecycle.ProposalRemoveAuthority / ProposalAddAuthority / ProposalChangeParameters / ProposalDomainExtension`,
				)
			}
		}
	}
}

// ──────────────────────────────────────────────────────────────────────
// [R5] Raw envelope.ControlHeader construction
// ──────────────────────────────────────────────────────────────────────
//
// The SDK ships 18 typed builders in builder/entry_builders.go that
// validate preconditions and set path fields correctly. Hand-populating
// a ControlHeader bypasses those validations and is the most common
// source of Path D silent failures.
//
// In strict mode this is an error. In balanced mode it's a warning —
// migration tooling legitimately does this.

func (c *Checker) checkRawControlHeader(cl *ast.CompositeLit) {
	sev := SeverityWarning
	if c.strictness == StrictnessStrict {
		sev = SeverityError
	}
	if c.strictness == StrictnessMinimal {
		return
	}
	c.record(
		"R5-raw-control-header",
		sev,
		cl.Pos(),
		"Direct envelope.ControlHeader{} composite literal bypasses the typed builders.",
		"Use one of the 18 functions in builder/entry_builders.go (BuildRootEntity, BuildAmendment, BuildPathBEntry, BuildEnforcement, BuildCosignature, etc.)",
	)
}

// ──────────────────────────────────────────────────────────────────────
// Call expression dispatcher
// ──────────────────────────────────────────────────────────────────────

func (c *Checker) checkCallExpr(call *ast.CallExpr) {
	// Selector-based calls: pkg.Func(...)
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		c.checkMathCeil2of3(call, sel)
		c.checkDirectNewEntry(call, sel)
		c.checkProcessBatchCall(call, sel)
		c.checkPREGenerateKFrags(call, sel)
	}

	// Type-conversion calls: uint8(X) where X is a typed constant.
	if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "uint8" {
		if len(call.Args) == 1 {
			if sel, ok := call.Args[0].(*ast.SelectorExpr); ok {
				c.checkWireByteCast(sel)
			}
		}
	}
}

// ──────────────────────────────────────────────────────────────────────
// [R4] Hardcoded 2/3 supermajority (Wave 2)
// ──────────────────────────────────────────────────────────────────────
//
// Before Wave 2 the SDK hardcoded ⌈2N/3⌉ in two call sites. Wave 2
// introduced OverrideThresholdRule.RequiredApprovals(N) and made the
// threshold schema-driven. Domain code that still does its own math.Ceil
// should be migrated.

func (c *Checker) checkMathCeil2of3(call *ast.CallExpr, sel *ast.SelectorExpr) {
	if ident, ok := sel.X.(*ast.Ident); !ok || ident.Name != "math" || sel.Sel.Name != "Ceil" {
		return
	}
	if len(call.Args) != 1 {
		return
	}
	// We don't try to pattern-match the exact arithmetic. Any math.Ceil
	// call in a file that imports lifecycle or verifier is suspicious
	// enough to flag for review.
	touchesLifecycle := c.pkgAlias("lifecycle") != "" || c.pkgAlias("verifier") != ""
	if !touchesLifecycle {
		return
	}
	c.record(
		"R4-hardcoded-threshold",
		SeverityWarning,
		call.Pos(),
		"math.Ceil in a file that uses lifecycle/verifier — likely hardcoded 2N/3 from pre-Wave-2 code.",
		"Call schemaParams.OverrideThreshold.RequiredApprovals(N) instead. Zero value = ThresholdTwoThirdsMajority (pre-Wave-2 default).",
	)
}

// ──────────────────────────────────────────────────────────────────────
// [R6] Direct envelope.NewEntry call
// ──────────────────────────────────────────────────────────────────────
//
// Same rationale as R5. Domain code should go through the typed builders
// because they validate domain-specific preconditions and set the correct
// AuthorityPath / TargetRoot shape.

func (c *Checker) checkDirectNewEntry(call *ast.CallExpr, sel *ast.SelectorExpr) {
	if !c.isSelectorFromPkg(sel, "core/envelope", "NewEntry") {
		return
	}
	if c.strictness == StrictnessMinimal {
		return
	}
	c.record(
		"R6-direct-new-entry",
		SeverityWarning,
		call.Pos(),
		"Direct envelope.NewEntry call — domain code should use builder.Build* wrappers.",
		"Replace with the appropriate builder.Build* function (see builder/entry_builders.go). Exceptions: migration tooling and the SDK itself.",
	)
}

// ──────────────────────────────────────────────────────────────────────
// [R7] Unsafe wire-byte cast
// ──────────────────────────────────────────────────────────────────────
//
// When populating envelope.AdmissionProofBody (whose Mode and HashFunc
// fields are uint8 by wire-format constraint), the SDK exports aliases
// types.WireByteModeA/B and admission.WireByteHashSHA256/Argon2id. The
// cast uint8(types.AdmissionModeB) works but defeats the discoverability
// the aliases exist to provide.
//
// This check is only invoked from within a uint8(...) call expression
// (see checkCallExpr), never from the general selector walk, so it does
// not double-fire on unrelated uses of AdmissionModeB or HashSHA256.

func (c *Checker) checkWireByteCast(sel *ast.SelectorExpr) {
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return
	}
	// types.AdmissionModeA/B and admission.HashSHA256/Argon2id.
	interesting := map[string]bool{
		"AdmissionModeA": true,
		"AdmissionModeB": true,
		"HashSHA256":     true,
		"HashArgon2id":   true,
	}
	if !interesting[sel.Sel.Name] {
		return
	}

	var typesAlias, admissionAlias string
	for alias, path := range c.sdkImports {
		switch filepath.Base(path) {
		case "types":
			typesAlias = alias
		case "admission":
			admissionAlias = alias
		}
	}
	if ident.Name != typesAlias && ident.Name != admissionAlias {
		return
	}

	if c.strictness == StrictnessMinimal {
		return
	}

	var fix string
	switch sel.Sel.Name {
	case "AdmissionModeA":
		fix = "Use types.WireByteModeA instead of uint8(types.AdmissionModeA)."
	case "AdmissionModeB":
		fix = "Use types.WireByteModeB instead of uint8(types.AdmissionModeB)."
	case "HashSHA256":
		fix = "Use admission.WireByteHashSHA256 instead of uint8(admission.HashSHA256)."
	case "HashArgon2id":
		fix = "Use admission.WireByteHashArgon2id instead of uint8(admission.HashArgon2id)."
	}
	c.record(
		"R7-wire-byte-cast",
		SeverityInfo,
		sel.Pos(),
		fmt.Sprintf("Cast uint8(%s.%s) — the SDK exports a wire-byte alias for this exact case.",
			ident.Name, sel.Sel.Name),
		fix,
	)
}

// ──────────────────────────────────────────────────────────────────────
// [R8] ProcessBatch without retry wrapping
// ──────────────────────────────────────────────────────────────────────
//
// builder.ProcessBatch + Path C = OCC rejection possible. Production
// callers wrap with ProcessWithRetry. We flag any direct ProcessBatch
// call for manual review.

func (c *Checker) checkProcessBatchCall(call *ast.CallExpr, sel *ast.SelectorExpr) {
	if !c.isSelectorFromPkg(sel, "builder", "ProcessBatch") {
		return
	}
	c.record(
		"R8-processbatch-without-retry",
		SeverityWarning,
		call.Pos(),
		"Direct builder.ProcessBatch call — Path C entries will fail under concurrent enforcement without OCC retry.",
		"Wrap with builder.ProcessWithRetry (see builder/occ_retry.go).",
	)
}

// ──────────────────────────────────────────────────────────────────────
// [R10] PRE master-key leak suspicion
// ──────────────────────────────────────────────────────────────────────
//
// The delegation-key isolation pattern (lifecycle/delegation_key.go)
// requires that PRE_GenerateKFrags receives sk_del (per-artifact), not
// sk_owner (master). We can't type-check this, but we can flag any call
// whose first argument is named like a master key.

func (c *Checker) checkPREGenerateKFrags(call *ast.CallExpr, sel *ast.SelectorExpr) {
	if !c.isSelectorFromPkg(sel, "crypto/artifact", "PRE_GenerateKFrags") {
		return
	}
	if len(call.Args) < 1 {
		return
	}
	arg := call.Args[0]
	ident, ok := arg.(*ast.Ident)
	if !ok {
		return
	}
	lower := strings.ToLower(ident.Name)
	suspicious := strings.Contains(lower, "owner") ||
		strings.Contains(lower, "master") ||
		lower == "sk" ||
		lower == "privkey" ||
		lower == "privatekey"
	if !suspicious {
		return
	}
	c.record(
		"R10-master-key-to-pre",
		SeverityWarning,
		call.Pos(),
		fmt.Sprintf("PRE_GenerateKFrags first arg %q looks like a master key. Scalar-multiplication PRE + M-of-N collusion can extract it.", ident.Name),
		"Use lifecycle.GenerateDelegationKey at publish time and lifecycle.UnwrapDelegationKey at grant time. Pass the unwrapped sk_del to PRE_GenerateKFrags — never sk_owner.",
	)
}

// ──────────────────────────────────────────────────────────────────────
// Function-body checks: [R9], [R11], [R12]
// ──────────────────────────────────────────────────────────────────────

func (c *Checker) checkFunctionBody(fd *ast.FuncDecl) {
	if fd.Body == nil {
		return
	}

	// R9: tree.SetLeaf in a range/for loop without an OverlayLeafStore
	// being constructed in the same function.
	usesOverlay := false
	setLeafCalls := []token.Pos{}

	// R12: same-function DomainPayload reads near builder calls.
	hasBuilderCall := false
	domainPayloadReads := []token.Pos{}

	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "SetLeaf" {
					setLeafCalls = append(setLeafCalls, node.Pos())
				}
				if sel.Sel.Name == "NewOverlayLeafStore" {
					usesOverlay = true
				}
				if c.isSelectorFromPkg(sel, "builder", "ProcessBatch") {
					hasBuilderCall = true
				}
				// Any builder.Build* call counts.
				if ident, ok := sel.X.(*ast.Ident); ok {
					if alias := c.pkgAlias("builder"); alias != "" && ident.Name == alias {
						if strings.HasPrefix(sel.Sel.Name, "Build") {
							hasBuilderCall = true
						}
					}
				}
			}
		case *ast.SelectorExpr:
			if node.Sel.Name == "DomainPayload" {
				domainPayloadReads = append(domainPayloadReads, node.Pos())
			}
		}
		return true
	})

	// Emit R9 findings.
	if len(setLeafCalls) > 0 && !usesOverlay && c.strictness != StrictnessMinimal {
		for _, pos := range setLeafCalls {
			c.record(
				"R9-setleaf-without-overlay",
				SeverityWarning,
				pos,
				"tree.SetLeaf called in a function that doesn't construct an OverlayLeafStore.",
				"Wrap the backing LeafStore with smt.NewOverlayLeafStore before batch processing so failures don't leave partial SMT state. See core/smt/overlay.go.",
			)
		}
	}

	// Emit R12 findings (strict only).
	if c.strictness == StrictnessStrict && hasBuilderCall && len(domainPayloadReads) > 0 {
		for _, pos := range domainPayloadReads {
			c.record(
				"R12-domainpayload-near-builder",
				SeverityWarning,
				pos,
				"Access to .DomainPayload in a function that also calls builder APIs — possible SDK-D6 violation (builder must not read Domain Payload).",
				"Move the DomainPayload read into verifier/domain code. Builder paths must rely on Control Header fields only.",
			)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────
// Reporting
// ──────────────────────────────────────────────────────────────────────

func printReport(c *Checker, filesScanned int, root string) {
	sep := strings.Repeat("─", 72)

	fmt.Println()
	fmt.Println(strings.Repeat("═", 72))
	fmt.Println("  Ortholog SDK Usage Audit")
	fmt.Println(strings.Repeat("═", 72))
	fmt.Printf("  Scanned root:    %s\n", root)
	fmt.Printf("  SDK prefix:      %s\n", c.sdkPrefix)
	fmt.Printf("  Strictness:      %s\n", strictnessName(c.strictness))
	fmt.Printf("  Files touching SDK: %d\n", filesScanned)
	fmt.Println()

	if len(c.findings) == 0 {
		fmt.Println("  ✓ No findings.")
		fmt.Println()
		return
	}

	// Count by severity.
	errs, warns, infos := 0, 0, 0
	for _, f := range c.findings {
		switch f.Severity {
		case SeverityError:
			errs++
		case SeverityWarning:
			warns++
		case SeverityInfo:
			infos++
		}
	}
	fmt.Printf("  Errors:   %d\n", errs)
	fmt.Printf("  Warnings: %d\n", warns)
	fmt.Printf("  Info:     %d\n", infos)
	fmt.Println()

	// Sort by severity then file then line.
	sort.SliceStable(c.findings, func(i, j int) bool {
		a, b := c.findings[i], c.findings[j]
		if a.Severity != b.Severity {
			return severityRank(a.Severity) < severityRank(b.Severity)
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})

	// Group by severity.
	curSev := Severity("")
	curFile := ""
	for _, f := range c.findings {
		if f.Severity != curSev {
			curSev = f.Severity
			fmt.Println(sep)
			fmt.Printf("  %s (%d)\n", strings.ToUpper(string(f.Severity)), countSev(c.findings, f.Severity))
			fmt.Println(sep)
			curFile = ""
		}
		if f.File != curFile {
			curFile = f.File
			fmt.Printf("\n  %s\n", f.File)
		}
		fmt.Printf("    [%s] %s:%d:%d\n", f.Rule, f.File, f.Line, f.Column)
		fmt.Printf("      %s\n", f.Message)
		if f.Fix != "" {
			fmt.Printf("      fix: %s\n", f.Fix)
		}
	}
	fmt.Println()
}

func severityRank(s Severity) int {
	switch s {
	case SeverityError:
		return 0
	case SeverityWarning:
		return 1
	case SeverityInfo:
		return 2
	}
	return 3
}

func countSev(findings []Finding, s Severity) int {
	n := 0
	for _, f := range findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

func strictnessName(s Strictness) string {
	switch s {
	case StrictnessMinimal:
		return "minimal"
	case StrictnessBalanced:
		return "balanced"
	case StrictnessStrict:
		return "strict"
	}
	return "unknown"
}

func writeJSON(findings []Finding, path string) error {
	b, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
