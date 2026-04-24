.PHONY: fmt build test check audit-v775 audit-v775-validate audit-v775-list audit-v775-full

fmt:
	@goimports -w $(shell find . -name '*.go' -not -path './vendor/*')
	@gofmt -w .

build:
	@go build ./...

test:
	@go test ./...

check: fmt build test
	@echo "✓ formatted, builds, and tests pass"

# ─────────────────────────────────────────────────────────────────
# Mutation-audit discipline (ADR-005 §6, Phase C Group 4)
# ─────────────────────────────────────────────────────────────────

# audit-v775 is the fast pre-commit gate. It validates every
# *.mutation-audit.yaml registry against the source files and test
# symbols it references without running any tests. Exits 3 on
# drift; 0 on clean.
audit-v775: audit-v775-validate

audit-v775-validate:
	@go run ./cmd/audit-v775 mutation --validate-registries

audit-v775-list:
	@go run ./cmd/audit-v775 mutation --list

# audit-v775-full executes every mutation probe end-to-end: for
# each gate, flips the constant, runs the binding tests, asserts
# they fail, restores, asserts they pass. Appends a dated section
# to docs/audit/mutation-audit-log.md. Exits 4 on discipline
# breakage (switch not load-bearing, test suite unstable, or
# restore failed).
#
# Slow (~1–2s per gate × 17 gates). Not wired into pre-commit.
# CI and pre-release gates call this.
audit-v775-full:
	@go run ./cmd/audit-v775 mutation
