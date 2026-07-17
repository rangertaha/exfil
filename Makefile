# exfil — developer task runner.
# Run `make` (or `make help`) to list targets.

CARGO ?= cargo
STORE ?= .exfil

.DEFAULT_GOAL := help
.PHONY: help build release install test cov fmt fmt-check lint check \
        run server tui scan docs docs-serve app clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Build the whole workspace (debug)
	$(CARGO) build --workspace

release: ## Build the CLI in release mode
	$(CARGO) build --release -p exfil-cli

install: ## Install the exfil binary onto your PATH
	$(CARGO) install --path crates/exfil-cli

test: ## Run all workspace tests
	$(CARGO) test --workspace

cov: ## Coverage summary (needs cargo-llvm-cov)
	$(CARGO) llvm-cov --workspace --summary-only

fmt: ## Format all code
	$(CARGO) fmt --all

fmt-check: ## Check formatting (no changes)
	$(CARGO) fmt --all --check

lint: ## Run clippy, denying warnings
	$(CARGO) clippy --workspace --all-targets -- -D warnings

check: fmt-check lint test ## Run the full CI gate (fmt, clippy, tests)

run: ## Run the CLI (pass ARGS="...")
	$(CARGO) run -p exfil-cli -- $(ARGS)

scan: ## Scan the current directory
	$(CARGO) run -p exfil-cli -- --store $(STORE) scan

server: ## Run the HTTP/GraphQL API server
	$(CARGO) run -p exfil-cli -- --store $(STORE) server

tui: ## Open the interactive TUI
	$(CARGO) run -p exfil-cli -- --store $(STORE) tui

docs: ## Build the mdBook docs site
	mdbook build docs

docs-serve: ## Serve the docs with live reload
	mdbook serve docs

app: ## Run the Tauri desktop app (needs the Tauri toolchain)
	cd app && EXFIL_BIN=../target/debug/exfil $(CARGO) tauri dev

clean: ## Remove build artifacts
	$(CARGO) clean
