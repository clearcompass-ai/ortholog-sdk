.PHONY: fmt build test check

fmt:
	@goimports -w $(shell find . -name '*.go' -not -path './vendor/*')
	@gofmt -w .

build:
	@go build ./...

test:
	@go test ./...

check: fmt build test
	@echo "✓ formatted, builds, and tests pass"
