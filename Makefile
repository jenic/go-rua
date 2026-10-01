# Basic Makefile for go-rua

TS := $(shell date +%Y%M%d)
COMMIT=$(shell git describe --long --tags --dirty --always | sed 's/^v//;s/\([^-]*-\)g/r\1/;s/-/./g;s/dirty/dirty_$(TS)/g')
GO ?= go
GOTOOLCHAIN ?= auto
GOPATH ?= $(CURDIR)/.gopath
GOCACHE ?= $(CURDIR)/.gocache
GOMODCACHE ?= $(CURDIR)/.gomodcache
PUBLISH ?= 0
BINARY := go-rua
BIN_DIR := bin
CMD_DIR := ./cmd/go-rua
OUT := $(BIN_DIR)/$(BINARY)
PKG := ./...
LDFLAGS=-X main.Version=${COMMIT}
GOFLAGS=-ldflags="${LDFLAGS}" -buildmode=pie
GOENV := GOPATH=$(GOPATH) GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOTOOLCHAIN=$(GOTOOLCHAIN)
CACHE_DIRS := $(GOPATH) $(GOCACHE) $(GOMODCACHE)

.PHONY: help build build-actual sast run fmt vet verify test check smoke integration-upgrade install publish-check publish clean

help: ## Show available make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .+$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-10s\033[0m %s\n", $$1, $$2}'

$(CACHE_DIRS):
	@mkdir -p $@

build-actual: fmt vet verify
	@mkdir -p $(BIN_DIR)
	$(GOENV) $(GO) build -o $(OUT) ${GOFLAGS} $(CMD_DIR)

# This is SAST, but it runs after every build.
sast: build-actual
	@echo "Checking binary for vulnerabilities..."
	$(GOENV) govulncheck -mode binary $(OUT)

build: sast ## Format, vet, verify, build, and scan the binary

run: build ## Run the CLI (usage: make run ARGS="version")
	$(OUT) $(ARGS)

fmt: $(CACHE_DIRS) ## Format code with gofmt
	$(GOENV) $(GO) fmt $(PKG)

vet: $(CACHE_DIRS) ## Static analysis with go vet
	$(GOENV) $(GO) vet $(PKG)

verify: $(CACHE_DIRS) ## Verify module dependencies
	$(GOENV) $(GO) mod verify

test: fmt vet verify ## Format, vet, verify, and run tests
	$(GOENV) $(GO) test $(PKG)

smoke: build ## Run a short integration smoke test (best-effort)
	./scripts/smoke.sh

integration-upgrade: build-actual ## Exercise an Arch fixture build and isolated pacman transaction
	bash ./scripts/integration-upgrade.sh

check: fmt vet verify test build ## Format, vet, verify, test, build, and scan

install: fmt vet verify test build ## Check, build, scan, and install to /usr/local/bin
	sudo install -v -C -o root -g root -m 0755 $(OUT) /usr/local/bin/$(notdir $(OUT))

publish-check: ## Validate a release (usage: make publish-check VERSION=v0.1.0)
	@VERSION='$(VERSION)' ./publish.sh check

publish: publish-check test ## Test, sign, tag, and publish a release
	@VERSION='$(VERSION)' PUBLISH='$(PUBLISH)' ./publish.sh publish

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)
