# Basic Makefile for go-rua

GO ?= go
BINARY := go-rua
BIN_DIR := bin
CMD_DIR := ./cmd/go-rua
OUT := $(BIN_DIR)/$(BINARY)
PKG := ./...

.PHONY: help build run fmt vet test check clean

help: ## Show available make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .+$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-10s\033[0m %s\n", $$1, $$2}'

build: ## Build binary to bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(OUT) $(CMD_DIR)

run: build ## Run the CLI (usage: make run ARGS="version")
	$(OUT) $(ARGS)

fmt: ## Format code with gofmt
	$(GO) fmt $(PKG)

vet: ## Static analysis with go vet
	$(GO) vet $(PKG)

test: ## Run tests
	$(GO) test $(PKG)

check: fmt vet test ## Format, vet, and test

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)

