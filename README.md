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

# Start as MCP server (for IDE integration)
pkg-guard serve
```

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

## Supported Ecosystems

| Ecosystem | Registry | Dependency Files | Lock Files |
|-----------|----------|-----------------|------------|
| Python | PyPI | requirements.txt | Pipfile.lock |
| npm | npmjs.org | package.json | package-lock.json, yarn.lock |
| Java | Maven Central | pom.xml, build.gradle | — |

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
└── data/            # Embedded blocklists & shared types
```

## License

MIT
