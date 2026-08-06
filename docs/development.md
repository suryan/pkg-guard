# Development Guide

## Prerequisites

- **Rust 1.70+** — install via [rustup](https://rustup.rs/)
- **Docker** — for running container audit tests (optional for basic development)
- **cargo-watch** (optional) — for hot-reloading during development

## Getting Started

```bash
# Clone
git clone <repo-url>
cd pkg-guard

# Build (debug)
cargo build

# Run tests
cargo test

# Run with hot-reload (requires cargo-watch)
cargo watch -x test -x 'run -- check -e python -p requests'
```

## Project Layout

```
pkg-guard/
├── Cargo.toml           # Dependencies and build config
├── scripts/
│   └── precommit.sh     # fmt, clippy, tests+coverage (≥90% lines), dogfood
├── src/
│   ├── main.rs          # Entry point, CLI + multicall shim dispatch
│   ├── mcp/             # JSON-RPC MCP server (protocol, server, tools)
│   ├── typosquat/       # Similarity / homoglyph detection
│   ├── registry/        # PyPI, npm, Maven, crates.io clients
│   ├── parsers/         # Dependency + lockfile parsers
│   ├── audit/           # Container orchestrator (bollard)
│   ├── project/         # Whole-repo audit
│   ├── osv/             # OSV.dev version advisories
│   ├── shim/            # Transparent pip/npm/cargo multicall
│   ├── data/            # Blocklist stack + shared types
│   │   ├── blocklist.rs          # Lookup: custom → feed (no embedded denylist)
│   │   ├── blocklist_format.rs   # Shared JSON schema
│   │   ├── custom_blocklist.rs   # User/project custom lists
│   │   ├── feed_cache.rs         # update-db cache
│   │   └── update_db.rs          # Remote feed refresh
│   ├── extra_coverage_tests.rs   # Broad unit tests for coverage gate
│   └── coverage_boost_tests.rs   # Additional coverage-oriented tests
├── data/blocklist/      # popular.json, example-feed, default-feeds
├── docs/
└── target/              # Build output (gitignored)
```

## Build Commands

```bash
# Debug build (fast compile, slow runtime)
cargo build

# Release build (slow compile, fast + small binary)
cargo build --release

# Check without building (fastest feedback)
cargo check

# Run clippy lints
cargo clippy -- -W clippy::all

# Format code
cargo fmt

# Run all tests
cargo test

# Run a specific test
cargo test test_typosquat_detected

# Coverage (required by precommit; default min 90% lines)
cargo install cargo-llvm-cov --locked   # once
rustup component add llvm-tools-preview # once
cargo llvm-cov --summary-only \
  --ignore-filename-regex 'main\.rs' \
  --fail-under-lines 90
cargo llvm-cov --html --output-dir target/llvm-cov   # HTML report
# Override threshold only with intentional review:
#   PKG_GUARD_MIN_COVERAGE=85 bash scripts/precommit.sh

# Full precommit gate (what CI / commit hygiene should run)
bash scripts/precommit.sh

# Run with verbose output
RUST_LOG=debug cargo run -- check -e python -p reqeusts
```

## Testing

### Unit Tests

Modules carry inline `#[cfg(test)]` tests; additional coverage-oriented suites live in
`src/extra_coverage_tests.rs` and `src/coverage_boost_tests.rs`.

```bash
# All tests
cargo test

# Tests for a specific module
cargo test typosquat
cargo test parsers
cargo test audit

# Coverage summary (same tool as precommit step 4)
cargo llvm-cov --summary-only --ignore-filename-regex 'main\.rs'
```

### Coverage policy

| Rule | Detail |
|------|--------|
| Minimum | **90% line** coverage (`--fail-under-lines 90`) |
| Scope | All of `src/` **except** `main.rs` (CLI/multicall entrypoint) |
| Tool | [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) + `llvm-tools-preview` |
| Override | `PKG_GUARD_MIN_COVERAGE=<n>` for local experiments only |
| File size | Each `src/**/*.rs` file must stay ≤ **1000** lines (precommit step 1) |

`main.rs` is excluded because it is process entry + `exec`/stdio wiring; behavior is exercised via library unit tests, shim helpers, and the Cargo.lock dogfood step.

### Manual Testing

```bash
# Typosquat check
cargo run -- check -e python -p reqeusts
cargo run -- check -e npm -p expresss
cargo run -- check -e java -p "org.springframework:spring-cor"

# Pin analysis
cargo run -- pin -f /path/to/requirements.txt
cargo run -- pin -f /path/to/package.json

# Lock file scan
cargo run -- scan -f /path/to/package-lock.json

# Full audit (requires Docker)
cargo run -- audit -e python -p requests -v 2.31.0
```

### Testing the MCP Server

```bash
# Start the server
cargo run -- serve

# In another terminal, send a JSON-RPC request:
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | cargo run -- serve

# Or use a tool call:
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | cargo run -- serve
```

## Adding a New Tool

1. **Define the tool schema** in `src/mcp/tools.rs`:
   ```rust
   ToolDefinition {
       name: "my_new_tool".to_string(),
       description: "What it does".to_string(),
       input_schema: json!({ ... }),
   }
   ```

2. **Implement the handler** in the appropriate module (or create a new one)

3. **Wire it up** in `src/mcp/server.rs`:
   ```rust
   "my_new_tool" => handle_my_new_tool(&arguments).await,
   ```

4. **Add a CLI subcommand** in `src/main.rs` if it should be usable standalone

5. **Add tests**

## Blocklist data (no denylist in the binary)

**Name denylists are never compiled into `pkg-guard`.** Supply them via custom files and/or remote feeds.

### Custom lists (zero-day)

```bash
pkg-guard blocklist init
# edit ~/.config/pkg-guard/blocklist.json
pkg-guard blocklist reload   # optional; mtime auto-reload for MCP
```

### Feed cache (`update-db`)

```bash
# Host data/blocklist/example-feed.json (or your own) somewhere
pkg-guard update-db --feed https://example.com/blocklist.json
# or: PKG_GUARD_FEED_URLS=url1,url2 pkg-guard update-db
```

Writes `~/.cache/pkg-guard/blocklist-cache.json` (override with `PKG_GUARD_CACHE_DIR`).
Lookup order: **custom → feed cache**.

### Popular packages (typosquat only — not a denylist)

Edit `data/blocklist/popular.json` and rebuild. Used only for similarity checks
against legitimate package names.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `RUST_LOG` | Tracing filter (e.g., `debug`, `pkg_guard=trace`) |
| `DOCKER_HOST` | Docker daemon address (defaults to local socket) |
| `PKG_GUARD_BLOCKLIST` | Path to an extra custom blocklist JSON file |
| `PKG_GUARD_FEED_URLS` | Comma-separated remote feed URLs for `update-db` |
| `PKG_GUARD_CACHE_DIR` | Override feed cache directory (default `~/.cache/pkg-guard`) |
| `PKG_GUARD_MIN_COVERAGE` | Precommit line-coverage floor (default **90**) |
| `PKG_GUARD_SHIM_MODE` | Shim policy: `enforce` (default), `warn`, or `off` |
| `PKG_GUARD_REAL_<TOOL>` | Absolute path to real package manager (avoids shim recursion) |
| `XDG_CONFIG_HOME` / `XDG_CACHE_HOME` | Standard XDG roots for config/cache |

## CI/CD Integration

```yaml
# Example GitHub Actions step
- name: Security check
  run: |
    pkg-guard pin -f requirements.txt
    pkg-guard scan -f package-lock.json
```

## Release Process

```bash
# Bump version in Cargo.toml
# Build release binary
cargo build --release

# Binary at: target/release/pkg-guard
ls -la target/release/pkg-guard

# Cross-compile for other targets (requires cross)
cross build --release --target x86_64-unknown-linux-musl
cross build --release --target x86_64-apple-darwin
cross build --release --target aarch64-apple-darwin
```

## Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| Rust over Python | Single binary, no runtime deps, memory safety for security tooling |
| bollard over docker CLI | No subprocess shelling, better error handling, typed API |
| reqwest + rustls | No OpenSSL dependency, simpler cross-compilation |
| No denylist in the binary | Name intel only from custom + feed cache; popular.json is typosquat-only |
| LazyLock over once_cell | Standard library (Rust 1.80+), no extra dependency |
| Simple XML parsing | Avoids xml crate dependency for pom.xml, keeps binary small |
| strsim crate | Battle-tested string similarity algorithms |
