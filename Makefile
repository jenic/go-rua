# Basic Makefile for go-rua

TS := $(shell date +%Y%M%d)
COMMIT=$(shell git describe --long --tags --dirty --always | sed 's/^v//;s/\([^-]*-\)g/r\1/;s/-/./g;s/dirty/dirty_$(TS)/g')
GO ?= go
GOTOOLCHAIN ?= go1.26.10
GOPATH ?= $(CURDIR)/.gopath
GOCACHE ?= $(CURDIR)/.gocache
GOMODCACHE ?= $(CURDIR)/.gomodcache
PUBLISH ?= 0
VERSION ?= dev
RELEASE_REMOTE ?= github
RELEASE_BINARY ?=
GOVULNCHECK_VERSION := v1.8.0
MODFLAGS := -mod=readonly
export VERSION RELEASE_REMOTE RELEASE_BINARY PUBLISH GO
BINARY := go-rua
BIN_DIR := bin
CMD_DIR := ./cmd/go-rua
OUT := $(BIN_DIR)/$(BINARY)
PKG := ./...
LDFLAGS=-X main.Version=${COMMIT}
GOFLAGS=-ldflags="${LDFLAGS}" -buildmode=pie
GOENV := GOWORK=off GOPATH=$(GOPATH) GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOTOOLCHAIN=$(GOTOOLCHAIN)
CACHE_DIRS := $(GOPATH) $(GOCACHE) $(GOMODCACHE)

.PHONY: help deps build build-actual sast run fmt vet verify test check smoke integration-upgrade integration-landlock install publish-check publish clean release-all verify-repro test-release test-release-binary vuln-binary

help: ## Show available make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .+$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-10s\033[0m %s\n", $$1, $$2}'

$(CACHE_DIRS):
	@mkdir -p $@

deps: verify ## Download pinned dependencies into local caches and verify them
	$(GOENV) $(GO) mod download
	$(MAKE) verify

build-actual: fmt vet verify
	@mkdir -p $(BIN_DIR)
	$(GOENV) $(GO) build $(MODFLAGS) -o $(OUT) ${GOFLAGS} $(CMD_DIR)

# This is SAST, but it runs after every build.
sast: build-actual
	@echo "Checking binary for vulnerabilities..."
	$(MAKE) vuln-binary RELEASE_BINARY="$(abspath $(OUT))"

vuln-binary: verify ## Scan RELEASE_BINARY with the pinned vulnerability checker
	@test -n "$$RELEASE_BINARY" && test -f "$$RELEASE_BINARY"
	$(GOENV) $(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) -mode binary "$$RELEASE_BINARY"

build: sast ## Format, vet, verify, build, and scan the binary

run: build ## Run the CLI (usage: make run ARGS="version")
	$(OUT) $(ARGS)

fmt: verify ## Format code with gofmt
	$(GOENV) $(GO) fmt $(MODFLAGS) $(PKG)

vet: fmt ## Static analysis with go vet
	$(GOENV) $(GO) vet $(MODFLAGS) $(PKG)

verify: $(CACHE_DIRS) ## Verify module dependencies
	$(GOENV) $(GO) mod verify
	@landlock_replacement="$$($(GOENV) $(GO) list -m -f '{{if .Replace}}replaced{{end}}' github.com/landlock-lsm/go-landlock)" && test -z "$$landlock_replacement" || { echo "Cannot verify upstream Landlock dependency; replacements are prohibited" >&2; exit 1; }

test: fmt vet verify ## Format, vet, verify, and run tests
	$(GOENV) $(GO) test $(MODFLAGS) $(PKG)

smoke: build ## Run a short integration smoke test (best-effort)
	./scripts/smoke.sh

integration-upgrade: build-actual ## Exercise an Arch fixture build and isolated pacman transaction
	bash ./scripts/integration-upgrade.sh

integration-landlock: build-actual ## Require real kernel enforcement and verify the built CLI's Landlock dependency
	$(GOENV) RUA_REQUIRE_LANDLOCK_TESTS=1 RUA_LANDLOCK_TEST_BINARY=$(abspath $(OUT)) $(GO) test $(MODFLAGS) -count=1 -v -run '^TestLandlockIntegration' $(CMD_DIR)

release-all: verify ## Build a deterministic Linux amd64 archive (VERSION=dev by default)
	$(GOENV) $(GO) run $(MODFLAGS) ./internal/release -version "$$VERSION"

verify-repro: verify ## Compare two independent release builds and archives
	$(GOENV) $(GO) run $(MODFLAGS) ./internal/release -version "$$VERSION" -verify

test-release: ## Run offline release, publishing, and CI orchestration tests
	python3 -B -m unittest discover -s .github/scripts -p 'test_*.py'

test-release-binary: verify ## Test RELEASE_BINARY without rebuilding it; VERSION must match
	@test -n "$$RELEASE_BINARY" && test -x "$$RELEASE_BINARY"
	@test "$$("$$RELEASE_BINARY" version)" = "$$VERSION"
	"$$RELEASE_BINARY" --help >/dev/null
	$(MAKE) vuln-binary
	$(GOENV) RUA_REQUIRE_LANDLOCK_TESTS=1 RUA_LANDLOCK_TEST_BINARY="$$(realpath "$$RELEASE_BINARY")" $(GO) test $(MODFLAGS) -count=1 -v -run '^TestLandlockIntegration' $(CMD_DIR)

check: fmt vet verify test build integration-landlock ## Format, vet, verify, test, build, scan, and prove Landlock enforcement

install: fmt vet verify test build ## Check, build, scan, and install to /usr/local/bin
	sudo install -v -C -o root -g root -m 0755 $(OUT) /usr/local/bin/$(notdir $(OUT))

publish-check: ## Validate a release and its GitHub remote (VERSION=v0.1.0)
	@bash ./publish.sh check

publish: publish-check ## Check enforcement, sign, and push a release tag to RELEASE_REMOTE
	$(MAKE) check test-release
	@bash ./publish.sh publish

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)
