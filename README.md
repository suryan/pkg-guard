# pkg-guard

A single-binary package security guardian that audits software packages for supply chain attacks, typosquatting, and malicious code across Python, npm, and Java ecosystems.

Built in Rust for performance, safety, and zero-dependency deployment.

## Features

- **Typosquat Detection** — Levenshtein distance, Jaro-Winkler similarity, homoglyph detection, and common mutation pattern matching against 100+ popular packages per ecosystem
- **Container Auditing** — Installs packages in isolated Docker containers with hardened security (cap-drop ALL, memory limits, PID limits) and monitors network, filesystem, and process activity
- **Dependency Pinning Analysis** — Scans requirements.txt, package.json, pom.xml, and build.gradle for unpinned or loosely-pinned versions
- **Lock File Scanning** — Checks package-lock.json, yarn.lock, Pipfile.lock, and requirements.txt against an embedded blocklist of known malicious packages
- **Registry Metadata** — Fetches package info from PyPI, npm, and Maven Central without installing anything
- **MCP Server** — Runs as a Model Context Protocol server for IDE integration (Kiro, VS Code, etc.)
- **Standalone CLI** — Use directly from the terminal for CI/CD pipelines and ad-hoc checks

## Quick Start

```bash
# Build
cargo build --release

# Check a package for typosquatting
pkg-guard check -e python -p reqeusts
# → BLOCKED — package is on the known-malicious blocklist

# Scan your dependencies for pinning issues
pkg-guard pin -f requirements.txt
# → WARNING: 6 dependencies are not pinned to exact versions

# Full audit with container isolation
pkg-guard audit -e npm -p express -v 4.18.2
# → PASS — safe to install

# Scan a lock file for known malicious packages
pkg-guard scan -f package-lock.json
# → CLEAN — no known malicious packages found

# Audit an entire project tree (manifests + lockfiles)
pkg-guard project -p .
# → WARNING/CRITICAL/CLEAN summary across the repo

# Custom blocklist (block brand-new threats without waiting for feeds)
pkg-guard blocklist init              # scaffold ~/.config/pkg-guard/blocklist.json
pkg-guard blocklist status

# Load name blocklist from a remote feed (nothing embedded in the binary)
pkg-guard update-db --feed https://example.com/blocklist.json

# Start as MCP server (for IDE integration)
pkg-guard serve

# Transparent PM shims (looks like pip/npm/cargo, gates installs)
pkg-guard shim install --dir ~/.local/bin
pkg-guard shim status
# PKG_GUARD_SHIM_MODE=enforce|warn|off
```

## Blocklist layers

**The binary embeds no name denylist.** Names come only from lists you load:

**Order:** custom → feed cache (`update-db`)

### Custom (zero-day)

| Path | Scope |
|------|--------|
| `PKG_GUARD_BLOCKLIST` env | Explicit file path |
| `~/.config/pkg-guard/blocklist.json` | User-wide |
| `.pkg-guard/blocklist.json` | Project (CWD) |

```bash
pkg-guard blocklist init
# edit JSON, then:
pkg-guard blocklist status
```

### Feed cache (required for shared name lists)

```bash
# Host data/blocklist/example-feed.json (or your own) and load it:
pkg-guard update-db --feed https://your-host/blocklist.json
# or: PKG_GUARD_FEED_URLS=url1,url2
```

Cache: `~/.cache/pkg-guard/blocklist-cache.json` (override with `PKG_GUARD_CACHE_DIR`).

### OSV version advisories

`audit` and `scan` query [OSV.dev](https://osv.dev) for the resolved package version
(CVEs and `MAL-*` malware IDs). Malware / CRITICAL / HIGH → BLOCK; other hits → WARN.

### What *is* embedded

- `data/blocklist/popular.json` — **legitimate** package names for typosquat similarity only (not a denylist)
- `data/blocklist/default-feeds.json` — optional default **feed URLs** (enable your own hosts)
- `data/blocklist/example-feed.json` — sample denylist document to **host yourself** (not compiled in)

## MCP Integration

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

The `audit_package` tool is intentionally not auto-approved since it launches Docker containers.

## MCP Tools

| Tool | Description |
|------|-------------|
| `audit_package` | Full audit with container isolation |
| `check_typosquat` | Typosquat detection against popular packages |
| `pin_dependencies` | Scan dependency files for unpinned versions |
| `scan_lockfile` | Check lock files against malicious package blocklist |
| `get_package_metadata` | Fetch registry metadata without installing |
| `audit_project` | Scan an entire project tree for pins + malicious packages |
| `blocklist_status` | Custom / feed cache / seed status |
| `update_db` | Refresh feed cache (seed + default/remote feeds) |

## Supported Ecosystems

| Ecosystem | Registry | Dependency Files | Lock Files |
|-----------|----------|-----------------|------------|
| Python | PyPI | requirements.txt | Pipfile.lock |
| npm | npmjs.org | package.json | package-lock.json, yarn.lock |
| Java | Maven Central | pom.xml, build.gradle | — |
| Cargo / Rust | crates.io | — | Cargo.lock |

## Requirements

- **Rust 1.70+** for building
- **Docker** (optional) for container auditing — if Docker is unavailable, the audit tool skips container checks and still performs typosquat + metadata analysis

## Project Structure

```
src/
├── main.rs          # CLI entry point (clap)
├── mcp/             # MCP JSON-RPC server
│   ├── protocol.rs  # JSON-RPC 2.0 types
│   ├── server.rs    # Stdio server loop
│   └── tools.rs     # Tool definitions & schemas
├── typosquat/       # Typosquat detection engine
├── registry/        # PyPI, npm, Maven Central clients
├── parsers/         # Dependency file parsers
├── audit/           # Container audit orchestrator (bollard)
├── project/         # Whole-repo manifest + lockfile scanner
└── data/            # Blocklist stack + shared types
data/blocklist/      # popular.json (typosquat); example-feed.json (host yourself)
```

## License

MIT
