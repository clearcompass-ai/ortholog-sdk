/*
FILE PATH:

	cmd/codegraph/main.go

DESCRIPTION:

	Emits a complete JSON graph of the Go module to stdout.
	Nodes: packages, types, functions. Edges: imports, implements, calls.

KEY ARCHITECTURAL DECISIONS:
  - Static analysis only. CHA call graph (not RTA — RTA panics on generics).
  - Each collection stage wrapped in recover() so one panic can't blank the
    whole graph.
  - Every nil path on SSA/callgraph data is guarded explicitly; synthetic
    edges with nil call sites emit with Site="".
  - Deterministic sorted output — diff-friendly.
  - Module path(s) for filtering: auto-detects the current module, but
    -prefix flag overrides with one-or-more comma-separated prefixes.
    Critical for cross-module analysis — e.g. running from a consumer repo
    to study which SDK symbols it actually calls.

USAGE:

	codegraph                                                  # auto-detect module
	codegraph -prefix github.com/foo/bar                       # single prefix
	codegraph -prefix github.com/foo/bar,github.com/foo/sdk    # cross-module

	Any symbol (function, type, edge endpoint) whose package path starts
	with at least one of the prefixes is included in the output.
*/
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// -------------------------------------------------------------------------------------------------
// 1) Output schema
// -------------------------------------------------------------------------------------------------

type Graph struct {
	Module     string       `json:"module"`
	Prefixes   []string     `json:"prefixes"`
	Packages   []PackageN   `json:"packages"`
	Types      []TypeN      `json:"types"`
	Functions  []FunctionN  `json:"functions"`
	Implements []Implements `json:"implements"`
	Calls      []CallEdge   `json:"calls"`
}

type PackageN struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Imports   []string `json:"imports"`
	Files     []string `json:"files"`
	TestFiles []string `json:"test_files"`
}

type TypeN struct {
	ID       string `json:"id"`
	Package  string `json:"package"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Exported bool   `json:"exported"`
}

type FunctionN struct {
	ID       string `json:"id"`
	Package  string `json:"package"`
	Name     string `json:"name"`
	Receiver string `json:"receiver,omitempty"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Exported bool   `json:"exported"`
}

type Implements struct {
	Type      string `json:"type"`
	Interface string `json:"interface"`
}

type CallEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Site string `json:"site"`
}

// -------------------------------------------------------------------------------------------------
// 2) Prefix matcher
// -------------------------------------------------------------------------------------------------

// prefixMatcher answers "is this package path inside one of the configured
// module prefixes?" — used as the filter for every collection stage.
type prefixMatcher struct {
	prefixes []string
}

func (m prefixMatcher) matches(pkgPath string) bool {
	for _, p := range m.prefixes {
		if strings.HasPrefix(pkgPath, p) {
			return true
		}
	}
	return false
}

// -------------------------------------------------------------------------------------------------
// 3) Main
// -------------------------------------------------------------------------------------------------

var prefixFlag = flag.String("prefix", "",
	"comma-separated module prefix(es) to include (default: auto-detected current module)")

func main() {
	flag.Parse()

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedImports |
			packages.NeedDeps | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedSyntax | packages.NeedModule,
		Tests: true,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		fmt.Fprintln(os.Stderr, "codegraph: load:", err)
		os.Exit(1)
	}
	if packages.PrintErrors(pkgs) > 0 {
		fmt.Fprintln(os.Stderr, "codegraph: package load errors — output may be incomplete")
	}

	primary := detectModulePath(pkgs)
	matcher := buildMatcher(*prefixFlag, primary)
	if len(matcher.prefixes) == 0 {
		fmt.Fprintln(os.Stderr, "codegraph: no module prefix available — pass -prefix or run from inside a module")
		os.Exit(1)
	}

	g := &Graph{Module: primary, Prefixes: matcher.prefixes}

	runStage("packages/types/functions", func() {
		collectPackagesTypesFunctions(pkgs, matcher, g)
	})
	runStage("implements", func() {
		collectImplements(pkgs, matcher, g)
	})
	runStage("calls", func() {
		collectCallEdges(pkgs, matcher, g)
	})

	finalizeDeterministic(g)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(g); err != nil {
		fmt.Fprintln(os.Stderr, "codegraph: encode:", err)
		os.Exit(1)
	}
}

// buildMatcher resolves the final prefix list. Explicit -prefix flag wins;
// empty flag falls back to the auto-detected module path.
func buildMatcher(flagVal, detected string) prefixMatcher {
	var list []string
	if flagVal != "" {
		for _, p := range strings.Split(flagVal, ",") {
			if p = strings.TrimSpace(p); p != "" {
				list = append(list, p)
			}
		}
	} else if detected != "" {
		list = []string{detected}
	}
	return prefixMatcher{prefixes: list}
}

func runStage(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr,
				"codegraph: stage %q panicked: %v — continuing with partial output\n", name, r)
		}
	}()
	fn()
}

// -------------------------------------------------------------------------------------------------
// 4) Module path detection
// -------------------------------------------------------------------------------------------------

func detectModulePath(pkgs []*packages.Package) string {
	for _, p := range pkgs {
		if p.Module != nil && p.Module.Path != "" {
			return p.Module.Path
		}
	}
	f, err := os.Open("go.mod")
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module"))
		}
	}
	return ""
}

// -------------------------------------------------------------------------------------------------
// 5) Packages, types, functions
// -------------------------------------------------------------------------------------------------

func collectPackagesTypesFunctions(pkgs []*packages.Package, m prefixMatcher, g *Graph) {
	seenPkg := map[string]bool{}
	seenType := map[string]bool{}
	seenFunc := map[string]bool{}

	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p == nil || !m.matches(p.PkgPath) || seenPkg[p.PkgPath] {
			return
		}
		seenPkg[p.PkgPath] = true

		pn := PackageN{ID: p.PkgPath, Name: p.Name}
		for _, imp := range p.Imports {
			if imp != nil && m.matches(imp.PkgPath) {
				pn.Imports = append(pn.Imports, imp.PkgPath)
			}
		}
		for _, f := range p.GoFiles {
			if strings.HasSuffix(f, "_test.go") {
				pn.TestFiles = append(pn.TestFiles, f)
			} else {
				pn.Files = append(pn.Files, f)
			}
		}
		g.Packages = append(g.Packages, pn)

		if p.Types == nil {
			return
		}

		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if obj == nil || obj.Pkg() == nil {
				continue
			}
			pos := p.Fset.Position(obj.Pos())
			switch o := obj.(type) {
			case *types.TypeName:
				id := qualifiedName(obj)
				if seenType[id] {
					continue
				}
				seenType[id] = true
				g.Types = append(g.Types, TypeN{
					ID: id, Package: obj.Pkg().Path(), Name: obj.Name(),
					Kind: typeKind(o.Type()), File: pos.Filename, Line: pos.Line,
					Exported: obj.Exported(),
				})
			case *types.Func:
				id := funcID(o)
				if seenFunc[id] {
					continue
				}
				seenFunc[id] = true
				g.Functions = append(g.Functions, FunctionN{
					ID: id, Package: obj.Pkg().Path(), Name: obj.Name(),
					Receiver: receiverName(o), File: pos.Filename, Line: pos.Line,
					Exported: obj.Exported(),
				})
			}
		}

		if p.TypesInfo == nil {
			return
		}
		for _, file := range p.Syntax {
			if file == nil {
				continue
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn == nil || fn.Recv == nil || fn.Name == nil {
					continue
				}
				def := p.TypesInfo.Defs[fn.Name]
				if def == nil {
					continue
				}
				obj, ok := def.(*types.Func)
				if !ok || obj.Pkg() == nil {
					continue
				}
				id := funcID(obj)
				if seenFunc[id] {
					continue
				}
				seenFunc[id] = true
				pos := p.Fset.Position(fn.Pos())
				g.Functions = append(g.Functions, FunctionN{
					ID: id, Package: p.PkgPath, Name: obj.Name(),
					Receiver: receiverName(obj), File: pos.Filename, Line: pos.Line,
					Exported: obj.Exported(),
				})
			}
		}
	})
}

// -------------------------------------------------------------------------------------------------
// 6) Implements
// -------------------------------------------------------------------------------------------------

func collectImplements(pkgs []*packages.Package, m prefixMatcher, g *Graph) {
	var interfaces, concretes []*types.Named
	seenPkg := map[string]bool{}

	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p == nil || p.Types == nil || seenPkg[p.PkgPath] || !m.matches(p.PkgPath) {
			return
		}
		seenPkg[p.PkgPath] = true
		for _, name := range p.Types.Scope().Names() {
			tn, ok := p.Types.Scope().Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
				continue
			}
			if _, isIface := named.Underlying().(*types.Interface); isIface {
				interfaces = append(interfaces, named)
			} else {
				concretes = append(concretes, named)
			}
		}
	})

	seen := map[string]bool{}
	for _, c := range concretes {
		for _, i := range interfaces {
			iface, ok := i.Underlying().(*types.Interface)
			if !ok {
				continue
			}
			matched := false
			func() {
				defer func() { _ = recover() }()
				if types.Implements(c, iface) || types.Implements(types.NewPointer(c), iface) {
					matched = true
				}
			}()
			if !matched {
				continue
			}
			key := c.Obj().Pkg().Path() + "." + c.Obj().Name() + "->" +
				i.Obj().Pkg().Path() + "." + i.Obj().Name()
			if seen[key] {
				continue
			}
			seen[key] = true
			g.Implements = append(g.Implements, Implements{
				Type:      c.Obj().Pkg().Path() + "." + c.Obj().Name(),
				Interface: i.Obj().Pkg().Path() + "." + i.Obj().Name(),
			})
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 7) Call edges
// -------------------------------------------------------------------------------------------------

func collectCallEdges(pkgs []*packages.Package, m prefixMatcher, g *Graph) {
	prog, _ := ssautil.AllPackages(pkgs, ssa.BuilderMode(0))
	prog.Build()

	chaGraph := cha.CallGraph(prog)
	if chaGraph == nil {
		return
	}

	seen := map[string]bool{}

	_ = callgraph.GraphVisitEdges(chaGraph, func(e *callgraph.Edge) error {
		if e == nil || e.Caller == nil || e.Callee == nil ||
			e.Caller.Func == nil || e.Callee.Func == nil ||
			e.Caller.Func.Pkg == nil || e.Callee.Func.Pkg == nil ||
			e.Caller.Func.Pkg.Pkg == nil || e.Callee.Func.Pkg.Pkg == nil {
			return nil
		}
		callerPkg := e.Caller.Func.Pkg.Pkg.Path()
		calleePkg := e.Callee.Func.Pkg.Pkg.Path()
		if !m.matches(callerPkg) || !m.matches(calleePkg) {
			return nil
		}

		site := ""
		if e.Site != nil {
			pos := prog.Fset.Position(e.Site.Pos())
			if pos.Filename != "" {
				site = fmt.Sprintf("%s:%d", pos.Filename, pos.Line)
			}
		}

		from := callerPkg + "." + e.Caller.Func.Name()
		to := calleePkg + "." + e.Callee.Func.Name()
		key := from + "\x00" + to + "\x00" + site
		if seen[key] {
			return nil
		}
		seen[key] = true

		g.Calls = append(g.Calls, CallEdge{From: from, To: to, Site: site})
		return nil
	})
}

// -------------------------------------------------------------------------------------------------
// 8) Deterministic sorting
// -------------------------------------------------------------------------------------------------

func finalizeDeterministic(g *Graph) {
	sort.Strings(g.Prefixes)
	sort.Slice(g.Packages, func(i, j int) bool { return g.Packages[i].ID < g.Packages[j].ID })
	for i := range g.Packages {
		sort.Strings(g.Packages[i].Imports)
		sort.Strings(g.Packages[i].Files)
		sort.Strings(g.Packages[i].TestFiles)
	}
	sort.Slice(g.Types, func(i, j int) bool { return g.Types[i].ID < g.Types[j].ID })
	sort.Slice(g.Functions, func(i, j int) bool { return g.Functions[i].ID < g.Functions[j].ID })
	sort.Slice(g.Implements, func(i, j int) bool {
		if g.Implements[i].Interface != g.Implements[j].Interface {
			return g.Implements[i].Interface < g.Implements[j].Interface
		}
		return g.Implements[i].Type < g.Implements[j].Type
	})
	sort.Slice(g.Calls, func(i, j int) bool {
		if g.Calls[i].From != g.Calls[j].From {
			return g.Calls[i].From < g.Calls[j].From
		}
		if g.Calls[i].To != g.Calls[j].To {
			return g.Calls[i].To < g.Calls[j].To
		}
		return g.Calls[i].Site < g.Calls[j].Site
	})
}

// -------------------------------------------------------------------------------------------------
// 9) Helpers
// -------------------------------------------------------------------------------------------------

func typeKind(t types.Type) string {
	if t == nil {
		return "other"
	}
	switch t.Underlying().(type) {
	case *types.Struct:
		return "struct"
	case *types.Interface:
		return "interface"
	case *types.Signature:
		return "func"
	case *types.Map:
		return "map"
	case *types.Slice:
		return "slice"
	case *types.Array:
		return "array"
	case *types.Chan:
		return "chan"
	case *types.Basic:
		return "basic"
	}
	return "other"
}

func qualifiedName(obj types.Object) string {
	pkg := ""
	if obj.Pkg() != nil {
		pkg = obj.Pkg().Path()
	}
	return pkg + "." + obj.Name()
}

func funcID(f *types.Func) string {
	recv := receiverName(f)
	pkg := ""
	if f.Pkg() != nil {
		pkg = f.Pkg().Path()
	}
	if recv != "" {
		return pkg + ".(" + recv + ")." + f.Name()
	}
	return pkg + "." + f.Name()
}

func receiverName(f *types.Func) string {
	sig, ok := f.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return ""
	}
	recvType := sig.Recv().Type()
	if ptr, ok := recvType.(*types.Pointer); ok {
		recvType = ptr.Elem()
	}
	if named, ok := recvType.(*types.Named); ok {
		if named.Obj() != nil {
			return named.Obj().Name()
		}
	}
	return recvType.String()
}
