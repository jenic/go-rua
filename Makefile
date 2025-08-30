# Basic Makefile for go-rua

TS := $(shell date +%Y%M%d)
COMMIT=$(shell git describe --long --tags --dirty --always | sed 's/^v//;s/\([^-]*-\)g/r\1/;s/-/./g;s/dirty/dirty_$(TS)/g')
GO ?= go
BINARY := go-rua
BIN_DIR := bin
CMD_DIR := ./cmd/go-rua
OUT := $(BIN_DIR)/$(BINARY)
PKG := ./...
LDFLAGS=-X main.Version=${COMMIT}
GOFLAGS=-ldflags="${LDFLAGS}" -buildmode=pie

.PHONY: help build run fmt vet test check smoke clean

help: ## Show available make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .+$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-10s\033[0m %s\n", $$1, $$2}'

build: ## Build binary to bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(OUT) ${GOFLAGS} $(CMD_DIR)

run: build ## Run the CLI (usage: make run ARGS="version")
	$(OUT) $(ARGS)

fmt: ## Format code with gofmt
	$(GO) fmt $(PKG)

vet: ## Static analysis with go vet
	$(GO) vet $(PKG)

test: ## Run tests
	$(GO) test $(PKG)

smoke: build ## Run a short integration smoke test (best-effort)
	./scripts/smoke.sh

check: fmt vet test ## Format, vet, and test

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)
