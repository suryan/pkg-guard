# pkg-guard

A single-binary package security guardian for supply-chain risk: typosquatting,
malicious packages, unpinned dependencies, and known advisories across **Python**,
**npm**, **Java**, and **Cargo**.

Built in Rust for performance, safety, and zero-dependency deployment.

## Features

- **Typosquat detection** — Levenshtein, Jaro-Winkler, homoglyphs, and common mutation patterns against popular packages per ecosystem
- **Container auditing** — Install packages in hardened Docker containers (cap-drop ALL, memory/PID limits) and observe install behavior
- **Package-manager shims** — Transparent wrappers for `pip` / `npm` / `npx` / `uv` / `uvx` / `cargo` (and friends) that gate installs before the real tool runs
- **Dependency pinning** — Flag unpinned or loose versions in `requirements.txt`, `package.json`, `pom.xml`, and `build.gradle`
- **Lockfile scanning** — Check lockfiles against custom/feed name lists + OSV advisories
- **Registry metadata** — Query PyPI, npm, Maven Central, and crates.io without installing
- **MCP server** — Model Context Protocol integration for IDE agents (Kiro, VS Code, etc.)
- **Standalone CLI** — CI/CD and ad-hoc use from a single binary

## Quick start

```bash
# Build & install the binary
cargo build --release
make install                          # → ~/.local/bin/pkg-guard

# Check a package for typosquatting / blocklist hits
pkg-guard check -e python -p reqeusts

# Pin analysis on a manifest
pkg-guard pin -f requirements.txt

# Full audit (optional Docker isolation)
pkg-guard audit -e npm -p express -v 4.18.2

# Scan a lockfile (blocklist + OSV)
pkg-guard scan -f package-lock.json

# Whole-repo pass (manifests + lockfiles)
pkg-guard project -p .

# Blocklist & feeds (nothing embedded in the binary)
pkg-guard blocklist init
pkg-guard update-db --feed https://example.com/blocklist.json

# MCP server for IDEs
pkg-guard serve
```

## Package-manager shims

Shims make day-to-day installs safer without changing how you invoke tools.
When you run `pip install`, `npm install`, `uvx some-mcp-server`, etc., the
shim runs **policy checks first** (custom/feed blocklist + OSV when a version
is known), then `exec`s the **real** package manager.

| Tool | What gets gated |
|------|-----------------|
| `pip` / `pip3` | `install` package lines |
| `npm` / `yarn` / `pnpm` | install / add style commands |
| `npx` / `pnpm dlx` / `yarn dlx` | package + **transitive** runtime deps |
| `uv` / `uvx` | tool run / install forms; `uvx` expands transitive deps |
| `cargo` | `add` / install-like forms |
| `mvn` / `gradle` | multicall names reserved (see usage guide) |

This is especially useful for **MCP servers** started as `uvx pkg==…` or
`npx -y pkg@…` — those resolve transitive dependencies you never type by hand.

### Setup (recommended)

**Rule:** put shims in a **dedicated directory first on `PATH`**. Leave real
`uv` / `uvx` / `npx` / `pip` where their installers put them. Do **not** install
shims into `~/.local/bin` if that is where the real tools live.

```bash
make install
pkg-guard shim install
# → ~/.local/share/pkg-guard/shims/{pip,pip3,npm,npx,uvx,uv,cargo,…}
# subset:  pkg-guard shim install --tools uvx,uv,npx

# Prepend shims on PATH (persist via ~/.config/pkg-guard/shim.env)
export PATH="$HOME/.local/share/pkg-guard/shims:$PATH"

pkg-guard shim status
which -a uvx   # first hit = shim; second hit = real tool
```

Source `shim.env` from **both** `~/.bashrc` and `~/.profile` (login shells often
prepend `~/.local/bin` after bashrc). For IDE/MCP hosts, set the same `PATH`
in the host environment — many skip shell profiles.

| Mode | Env | Behavior |
|------|-----|----------|
| **enforce** (default) | `PKG_GUARD_SHIM_MODE=enforce` | Block on policy failure (exit 2) |
| **warn** | `PKG_GUARD_SHIM_MODE=warn` | Warn, still run the real tool |
| **off** | `PKG_GUARD_SHIM_MODE=off` | Fully transparent (no checks) |

```bash
pkg-guard shim uninstall   # removes shim links only; real tools untouched
```

Full guide (MCP PATH, anti-patterns, troubleshooting):
[docs/usage.md — Transparent package-manager shims](docs/usage.md#transparent-package-manager-shims).

## Blocklist layers

**The binary embeds no name denylist.** Names come only from lists you load.

**Order:** custom → feed cache (`update-db`)

### Custom (zero-day)

| Path | Scope |
|------|--------|
| `PKG_GUARD_BLOCKLIST` env | Explicit file path |
| `~/.config/pkg-guard/blocklist.json` | User-wide |
| `.pkg-guard/blocklist.json` | Project (CWD) |

```bash
pkg-guard blocklist init
pkg-guard blocklist status
```

### Feed cache (shared name lists)

```bash
pkg-guard update-db --feed https://your-host/blocklist.json
# or: PKG_GUARD_FEED_URLS=url1,url2
```

Cache: `~/.cache/pkg-guard/blocklist-cache.json` (override with `PKG_GUARD_CACHE_DIR`).

### OSV version advisories

`audit` and `scan` check package versions for CVEs / `MAL-*` IDs.

**Local dump (recommended for offline/CI):**

```bash
pkg-guard osv update
pkg-guard osv status
PKG_GUARD_OSV_MODE=local pkg-guard scan -f Cargo.lock
```

**Live API:** used when no local index exists, or with `PKG_GUARD_OSV_MODE=online`.

Default mode is **`auto`**: local index if present, else [api.osv.dev](https://osv.dev).
Malware / CRITICAL / HIGH → BLOCK; other hits → WARN.

### What *is* embedded

- `data/blocklist/popular.json` — **legitimate** names for typosquat similarity only (not a denylist)
- `data/blocklist/default-feeds.json` — optional default **feed URLs**
- `data/blocklist/example-feed.json` — sample denylist document to **host yourself** (not compiled in)

## MCP integration

Add to your Kiro/IDE MCP configuration:

```json
{
  "mcpServers": {
    "pkg-guard": {
      "command": "/path/to/pkg-guard",
      "args": ["serve"],
      "disabled": false,
      "autoApprove": ["check_typosquat", "get_package_metadata", "pin_dependencies", "scan_lockfile"]
    }
  }
}
```

`audit_package` is intentionally not auto-approved (it may launch Docker containers).

When MCP servers themselves launch via `uvx` / `npx`, put the **shim dir first**
on that host’s `PATH` (and prefer bare command names over absolute paths to the
real binary) so the gate is not skipped.

### MCP tools

| Tool | Description |
|------|-------------|
| `audit_package` | Full audit with optional container isolation |
| `check_typosquat` | Typosquat detection against popular packages |
| `pin_dependencies` | Scan manifests for unpinned versions |
| `scan_lockfile` | Lockfiles: custom/feed blocklists + OSV |
| `get_package_metadata` | Registry metadata without installing |
| `audit_project` | Whole-tree pins + malicious package scan |
| `blocklist_status` | Custom / feed-cache status |
| `update_db` | Refresh feed cache from remote URLs |

## Supported ecosystems

| Ecosystem | Registry | Dependency files | Lock files |
|-----------|----------|------------------|------------|
| Python | PyPI | requirements.txt | Pipfile.lock, requirements.txt |
| npm | npmjs.org | package.json | package-lock.json, yarn.lock |
| Java | Maven Central | pom.xml, build.gradle | — |
| Cargo / Rust | crates.io | — | Cargo.lock |

## Requirements

- **Rust 1.70+** to build
- **Docker** (optional) for container auditing — without it, audit still runs typosquat + metadata/OSV checks
- **cargo-llvm-cov** + `llvm-tools-preview` for the precommit coverage gate ([docs/development.md](docs/development.md))

## Development checks

```bash
make help          # list targets
make precommit     # full gate: fmt, clippy, tests, ≥90% coverage, dogfood
make release       # optimized binary → target/release/pkg-guard
make install       # install to ~/.local/bin
make test          # cargo test
make coverage      # line coverage summary
make osv-update    # download local OSV dumps (ECOSYSTEMS=cargo optional)
make scan          # scan FILE=Cargo.lock
make dogfood       # scan this repo's Cargo.lock
```

Or: `bash scripts/precommit.sh`

Coverage uses `cargo llvm-cov` on library modules (`main.rs` excluded). Override
the floor with `PKG_GUARD_MIN_COVERAGE` only for local experiments.

## Project structure

```
src/
├── main.rs          # CLI entry (clap) + multicall shim dispatch
├── mcp/             # MCP JSON-RPC server
├── typosquat/       # Typosquat detection engine
├── registry/        # PyPI, npm, Maven Central, crates.io clients
├── parsers/         # Dependency / lockfile parsers
├── audit/           # Container audit orchestrator (bollard)
├── project/         # Whole-repo manifest + lockfile scanner
├── osv/             # OSV.dev version advisories
├── shim/            # Transparent pip/npm/uvx/cargo multicall wrappers
└── data/            # Blocklist stack + shared types
data/blocklist/      # popular.json (typosquat); example-feed.json (host yourself)
scripts/precommit.sh # Quality gate (90% line coverage)
```

## Docs

| Doc | Contents |
|-----|----------|
| [docs/usage.md](docs/usage.md) | CLI, shims, blocklists, OSV, env vars, troubleshooting |
| [docs/architecture.md](docs/architecture.md) | Design overview |
| [docs/development.md](docs/development.md) | Build, test, coverage |
| [docs/product_requirements.md](docs/product_requirements.md) | Requirements |

## License

MIT
