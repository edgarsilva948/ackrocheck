BINARY      := ackrocheck
BIN_DIR     := bin
MODULE      := github.com/edgarsilva948/ackrocheck
# Resolve once via the shell so a stray non-binary `go` entry on PATH cannot
# break make's direct exec; overridable with `make GO=/path/to/go ...`.
GO          ?= $(shell command -v go)
VERSION     ?= dev
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE        := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
CONTROLS    ?= embedded-$(VERSION)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE) \
	-X $(MODULE)/internal/version.ControlsVersion=$(CONTROLS)

.PHONY: build test test-coverage lint run-example goreleaser-snapshot clean fmt vet

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) ./cmd/ackrocheck

test:
	$(GO) test ./...

test-coverage:
	$(GO) test ./... -coverprofile=coverage.out -covermode=atomic
	$(GO) tool cover -html=coverage.out -o coverage.html
	$(GO) tool cover -func=coverage.out | tail -1

lint:
	gofmt -l . | tee /dev/stderr | wc -l | grep -q '^0$$'
	$(GO) vet ./...

run-example: build
	-./$(BIN_DIR)/$(BINARY) scan ./testdata/fail ./testdata/kro --no-color

goreleaser-snapshot:
	goreleaser release --snapshot --clean

fmt:
	gofmt -w .

vet:
	$(GO) vet ./...

clean:
	rm -rf $(BIN_DIR) dist coverage.out coverage.html
