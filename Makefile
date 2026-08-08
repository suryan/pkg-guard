# pkg-guard — common developer tasks
# Usage: make <target>
# Run from the repository root (or any dir; recipes cd to ROOT).

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BIN  := $(ROOT)/target/release/pkg-guard
PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin

# Optional: make osv-update ECOSYSTEMS=cargo,python
ECOSYSTEMS ?=
# Optional: make scan FILE=path/to/lock
FILE ?= Cargo.lock
# Optional: make project PATH=.
PATH_DIR ?= .

# Global shims: MCP launchers only by default (uvx,uv,npx). Use SHIM_TOOLS=all for full set.
SHIM_TOOLS ?= uvx,uv,npx

.PHONY: help build release install uninstall test check fmt clippy precommit \
	coverage cov-html scan project dogfood osv-update osv-status \
	shim-install shim-status setup-user clean run-serve

help: ## Show this help
	@echo "pkg-guard make targets"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Variables: PREFIX=$(PREFIX)  FILE=$(FILE)  ECOSYSTEMS=$(ECOSYSTEMS)  SHIM_TOOLS=$(SHIM_TOOLS)"

# ─── build & install ──────────────────────────────────────────────────────────

build: ## Debug build
	cd $(ROOT) && cargo build

release: ## Release build (optimized)
	cd $(ROOT) && cargo build --release

install: release ## Install binary to BINDIR (default: ~/.local/bin)
	install -d "$(BINDIR)"
	install -m 755 "$(BIN)" "$(BINDIR)/pkg-guard"
	@echo "Installed: $(BINDIR)/pkg-guard"
	@echo "Ensure $(BINDIR) is on your PATH"

uninstall: ## Remove binary from BINDIR
	rm -f "$(BINDIR)/pkg-guard"
	@echo "Removed $(BINDIR)/pkg-guard (if present)"

# ─── quality ──────────────────────────────────────────────────────────────────

test: ## Run unit tests
	cd $(ROOT) && cargo test

check: ## Fast typecheck (no binary)
	cd $(ROOT) && cargo check

fmt: ## Format sources
	cd $(ROOT) && cargo fmt

clippy: ## Clippy with -D warnings
	cd $(ROOT) && cargo clippy -- -D warnings

precommit: ## Full gate (fmt, clippy, tests, ≥90% coverage, dogfood)
	cd $(ROOT) && bash scripts/precommit.sh

coverage: ## Line coverage summary (excludes main.rs; fail under 90%)
	cd $(ROOT) && cargo llvm-cov --summary-only \
		--ignore-filename-regex 'main\.rs' \
		--fail-under-lines "$${PKG_GUARD_MIN_COVERAGE:-90}"

cov-html: ## HTML coverage report → target/llvm-cov
	cd $(ROOT) && cargo llvm-cov --html --output-dir target/llvm-cov \
		--ignore-filename-regex 'main\.rs'
	@echo "Open: $(ROOT)/target/llvm-cov/html/index.html"

# ─── product commands (need release binary) ───────────────────────────────────

$(BIN):
	$(MAKE) release

scan: $(BIN) ## Scan a lockfile (FILE=Cargo.lock)
	"$(BIN)" scan -f "$(FILE)"

project: $(BIN) ## Audit a project tree (PATH_DIR=.)
	"$(BIN)" project -p "$(PATH_DIR)"

dogfood: $(BIN) ## Scan this repo's Cargo.lock
	"$(BIN)" scan -f "$(ROOT)/Cargo.lock"

osv-update: $(BIN) ## Download OSV dumps (ECOSYSTEMS=cargo,python or empty=all)
	@if [ -n "$(ECOSYSTEMS)" ]; then \
		"$(BIN)" osv update -e "$(ECOSYSTEMS)"; \
	else \
		"$(BIN)" osv update; \
	fi

osv-status: $(BIN) ## Show local OSV dump status
	"$(BIN)" osv status

# Shims go in a dedicated dir (not BINDIR) so real uv/uvx in ~/.local/bin stay put.
SHIMDIR ?= $(HOME)/.local/share/pkg-guard/shims

shim-install: $(BIN) ## Install global shims (default SHIM_TOOLS=uvx,uv,npx; or all)
	@tools="$(SHIM_TOOLS)"; \
	if [ "$$tools" = "all" ] || [ "$$tools" = "ALL" ]; then tools="pip,pip3,npm,npx,uvx,uv,cargo"; fi; \
	if [ "$$tools" = "mcp" ] || [ "$$tools" = "MCP" ]; then tools="uvx,uv,npx"; fi; \
	"$(BIN)" shim install --dir "$(SHIMDIR)" --tools "$$tools"
	@echo "Shims in $(SHIMDIR). Prefer: make setup-user  (writes shim.env + shell rc)"

shim-status: $(BIN) ## Show shim resolution status
	"$(BIN)" shim status --tools "$(SHIM_TOOLS)"

setup-user: install ## Binary + MCP shims + shim.env + shell rc (macOS/Linux)
	bash "$(ROOT)/scripts/setup-user.sh" --bin "$(BINDIR)/pkg-guard" --tools "$(SHIM_TOOLS)"

run-serve: $(BIN) ## Start MCP server (stdio)
	"$(BIN)" serve

# ─── maintenance ──────────────────────────────────────────────────────────────

clean: ## Remove cargo build artifacts
	cd $(ROOT) && cargo clean
