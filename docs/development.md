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
├── src/
│   ├── main.rs          # Entry point, CLI definition
│   ├── mcp/
│   │   ├── mod.rs       # Module exports
│   │   ├── protocol.rs  # JSON-RPC types
│   │   ├── server.rs    # MCP server loop
│   │   └── tools.rs     # Tool schemas
│   ├── typosquat/
│   │   └── mod.rs       # Detection algorithms
│   ├── registry/
│   │   └── mod.rs       # PyPI, npm, Maven clients
│   ├── parsers/
│   │   └── mod.rs       # Dependency file parsers
│   ├── audit/
│   │   └── mod.rs       # Container orchestrator
│   └── data/
│       ├── mod.rs       # Shared types
│       └── blocklist.rs # Embedded blocklists
├── docs/                # Documentation
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

# Run with verbose output
RUST_LOG=debug cargo run -- check -e python -p reqeusts
```

## Testing

### Unit Tests

Each module has inline `#[cfg(test)]` tests:

```bash
# All tests
cargo test

# Tests for a specific module
cargo test typosquat
cargo test parsers
cargo test audit
```

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

## Adding Packages to the Blocklist

Edit `src/data/blocklist.rs` and add entries to the appropriate `LazyLock<HashSet>`:

```rust
static PYTHON_BLOCKLIST: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        // ... existing entries ...
        "new-malicious-package",  // Add here
    ]
    .into_iter()
    .collect()
});
```

The blocklist is compiled into the binary — rebuild after changes.

## Adding Popular Packages (for Typosquat Detection)

Edit `src/data/blocklist.rs` and add to `POPULAR_*` vectors:

```rust
pub static POPULAR_PYTHON: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        // ... existing ...
        "new-popular-package",
    ]
});
```

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `RUST_LOG` | Tracing filter (e.g., `debug`, `pkg_guard=trace`) |
| `DOCKER_HOST` | Docker daemon address (defaults to local socket) |

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
| Embedded blocklists | Zero runtime file dependencies, atomic updates via rebuild |
| LazyLock over once_cell | Standard library (Rust 1.80+), no extra dependency |
| Simple XML parsing | Avoids xml crate dependency for pom.xml, keeps binary small |
| strsim crate | Battle-tested string similarity algorithms |
