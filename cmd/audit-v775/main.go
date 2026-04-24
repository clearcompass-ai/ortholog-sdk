// cmd/audit-v775 — v7.75 "Provenance" audit multi-tool.
//
// Two subcommands:
//
//   audit-v775 scope
//       Structural scope audit (original behavior). Walks the
//       Ortholog SDK AST to produce the v7.75 production / test
//       scope manifests under audits/. See scope.go.
//
//   audit-v775 mutation [flags]
//       Mutation-audit runner (ADR-005 §6). Reads every
//       *.mutation-audit.yaml registry in the repo, flips each
//       gate's constant (bool_const) or source string
//       (string_mutation), runs the listed binding tests, asserts
//       they fail, restores the source, runs the tests again,
//       asserts they pass. Records each gate's pass/fail entry
//       in docs/audit/mutation-audit-log.md with an ISO8601
//       timestamp. See mutation.go.
//
//       Flags:
//         --validate-registries
//             Load every registry and verify that each declared
//             gate constant exists in the named source file and
//             every declared test function exists in a _test.go
//             file under the registry's package. Exit 0 on no
//             drift; exit non-zero on drift.
//         --list
//             List every gate across every registry, one per
//             line, as "file:gate:kind". For debugging and CI.
//         --dry-run
//             Locate registries and prepare mutations, but do not
//             actually flip source or run tests. For CI wiring.
//         --only=<regexp>
//             Run only gates whose name matches the regexp.
//
// Usage from repo root:
//
//   go run ./cmd/audit-v775 scope
//   go run ./cmd/audit-v775 mutation
//   go run ./cmd/audit-v775 mutation --validate-registries
//   go run ./cmd/audit-v775 mutation --list
//
// Exit codes:
//
//   0  — subcommand succeeded
//   1  — load or runtime error (module won't compile, shell out
//        failed, I/O error)
//   2  — specification inconsistency (scope audit only)
//   3  — registry drift (mutation --validate-registries)
//   4  — mutation audit failed (a gate flipped false did NOT cause
//        the listed tests to fail, OR the restored state did NOT
//        restore passing tests — i.e., the discipline is broken)

package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	sub := os.Args[1]
	args := os.Args[2:]
	switch sub {
	case "scope":
		runScope()
	case "mutation":
		runMutation(args)
	case "-h", "--help", "help":
		usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "audit-v775: unknown subcommand %q\n\n", sub)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `audit-v775 — v7.75 Provenance audit multi-tool

Subcommands:

  scope       Structural scope audit (writes audits/*.md).
  mutation    Mutation-audit runner (reads *.mutation-audit.yaml).

Mutation flags:

  --validate-registries   Validate registries only; do not mutate.
  --list                  List every registered gate.
  --dry-run               Prepare mutations without running them.
  --only=<regexp>         Run only gates matching regexp.

See cmd/audit-v775/main.go for exit codes.`)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "audit-v775: "+format+"\n", args...)
	os.Exit(1)
}

func fatalWithCode(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "audit-v775: "+format+"\n", args...)
	os.Exit(code)
}
