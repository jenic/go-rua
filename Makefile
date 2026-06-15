# Basic Makefile for go-rua

TS := $(shell date +%Y%M%d)
COMMIT=$(shell git describe --long --tags --dirty --always | sed 's/^v//;s/\([^-]*-\)g/r\1/;s/-/./g;s/dirty/dirty_$(TS)/g')
GO ?= go
GOCACHE ?= $(CURDIR)/.gocache
GOMODCACHE ?= $(CURDIR)/.gomodcache
BINARY := go-rua
BIN_DIR := bin
CMD_DIR := ./cmd/go-rua
OUT := $(BIN_DIR)/$(BINARY)
PKG := ./...
LDFLAGS=-X main.Version=${COMMIT}
GOFLAGS=-ldflags="${LDFLAGS}" -buildmode=pie
GOENV := GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE)
CACHE_DIRS := $(GOCACHE) $(GOMODCACHE)

.PHONY: help build run fmt vet test check smoke clean

help: ## Show available make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .+$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-10s\033[0m %s\n", $$1, $$2}'

$(CACHE_DIRS):
	@mkdir -p $@

build: fmt ## Format code and build binary to bin/
	@mkdir -p $(BIN_DIR)
	$(GOENV) $(GO) build -o $(OUT) ${GOFLAGS} $(CMD_DIR)

run: build ## Run the CLI (usage: make run ARGS="version")
	$(OUT) $(ARGS)

fmt: $(CACHE_DIRS) ## Format code with gofmt
	$(GOENV) $(GO) fmt $(PKG)

vet: $(CACHE_DIRS) ## Static analysis with go vet
	$(GOENV) $(GO) vet $(PKG)

test: fmt ## Format code and run tests
	$(GOENV) $(GO) test $(PKG)

smoke: build ## Run a short integration smoke test (best-effort)
	./scripts/smoke.sh

check: fmt vet test build ## Format, vet, test, and build

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)
