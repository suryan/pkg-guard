# Architecture

## Overview

pkg-guard is a single-binary Rust application that serves two roles:
1. **MCP Server** — communicates over JSON-RPC 2.0 via stdio for IDE integration
2. **CLI Tool** — standalone commands for terminal and CI/CD use

Both interfaces share the same core modules. The binary compiles to ~8-12MB with release optimizations (LTO + strip).

## High-Level Components

```
┌─────────────────────────────────────────────────────────────┐
│                        pkg-guard                            │
├─────────────────────────────────────────────────────────────┤
│  CLI (clap)              │  MCP Server (JSON-RPC stdio)     │
│  ├─ audit                │  ├─ initialize                   │
│  ├─ check                │  ├─ tools/list                   │
│  ├─ pin                  │  └─ tools/call                   │
│  └─ scan                 │      ├─ audit_package            │
│                          │      ├─ check_typosquat          │
│                          │      ├─ pin_dependencies         │
│                          │      ├─ scan_lockfile            │
│                          │      └─ get_package_metadata     │
├──────────────────────────┴──────────────────────────────────┤
│                     Core Modules                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  typosquat   │  │   registry   │  │     parsers      │  │
│  │  ─────────   │  │   ────────   │  │     ───────      │  │
│  │  Levenshtein │  │  PyPI client │  │  requirements.txt│  │
│  │  Jaro-Winkler│  │  npm client  │  │  package.json    │  │
│  │  Homoglyphs  │  │  Maven client│  │  pom.xml         │  │
│  │  Patterns    │  │              │  │  build.gradle    │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│  ┌──────────────┐  ┌────────────────────────────────────┐  │
│  │    audit     │  │              data                   │  │
│  │    ─────     │  │              ────                   │  │
│  │  Docker API  │  │  Blocklist stack                    │  │
│  │  (bollard)   │  │  custom → feed cache → seed JSON    │  │
│  │  Container   │  │  Popular packages (data JSON)       │  │
│  │  orchestrate │  │  Shared types (Ecosystem, Results)  │  │
│  └──────────────┘  └────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Module Responsibilities

### `src/mcp/` — MCP Protocol Layer

- **protocol.rs** — JSON-RPC 2.0 request/response types, MCP capability negotiation
- **server.rs** — Async stdin reader, request routing, response serialization
- **tools.rs** — Tool definitions with JSON Schema for each tool's input

Design decisions:
- Reads line-delimited JSON from stdin (not HTTP) per MCP spec
- Responses written to stdout; logs/tracing go to stderr
- Notifications (no `id` field) are silently consumed
- All tool handlers are async to support concurrent registry calls

### `src/typosquat/` — Detection Engine

Multi-layered detection:
1. **Blocklist check** — O(1) HashSet lookup against known malicious names
2. **Levenshtein distance** — flags packages within edit distance ≤ 2 of popular packages
3. **Jaro-Winkler similarity** — catches prefix-similar names (threshold ≥ 0.85)
4. **Homoglyph detection** — identifies visual lookalikes (l/1, O/0, I/l)
5. **Pattern matching** — suffix tricks (-js, -py, -utils), version suffixes, separator variations

Name normalization is ecosystem-aware:
- Python/npm: strips hyphens, underscores, dots, lowercases
- Java: compares only the artifactId portion of groupId:artifactId

### `src/registry/` — Registry Clients

Async HTTP clients using reqwest with rustls:
- **PyPI** — `https://pypi.org/pypi/{name}/json` and version-specific endpoints
- **npm** — `https://registry.npmjs.org/{name}` with install script detection
- **Maven Central** — Solr search API for groupId + artifactId resolution

All clients:
- 15-second timeout
- Graceful 404 handling (returns `{exists: false}`)
- Custom user-agent for rate limiting transparency

### `src/parsers/` — Dependency File Analysis

Two distinct operations:
1. **pin_dependencies** — Analyzes version constraints, classifies as pinned/unpinned
2. **scan_lockfile** — Checks resolved packages against blocklist

Supported formats:
- Python: requirements.txt (==, >=, ~=, bare names), Pipfile.lock
- npm: package.json (^, ~, *, ranges), package-lock.json, yarn.lock
- Java: pom.xml (LATEST, RELEASE, SNAPSHOT, ${var}), build.gradle

Design choice: Simple string/regex parsing instead of full XML/TOML parsers to minimize binary size and dependency count.

### `src/audit/` — Container Orchestrator

Uses bollard (Docker API bindings) instead of shelling out to `docker` CLI:
- Pulls ecosystem-specific base images (python:3.12-slim, node:20-slim, maven:3.9)
- Creates hardened containers (cap-drop ALL, 512MB memory, 100 PIDs, no-new-privileges)
- Injects an audit shell script that monitors install behavior
- Collects stdout/stderr logs
- Parses JSON results from container output
- 120-second timeout with automatic cleanup

Container security posture:
- Only NET_RAW capability added (for network monitoring within container)
- Read-only sensitive paths
- PID limit prevents fork bombs
- Memory limit prevents resource exhaustion

### `src/data/` — Shared State & Blocklist Stack

| Module | Role |
|--------|------|
| `blocklist.rs` | Lookup order + seed load (`include_str!` of `data/blocklist/seed.json`) |
| `blocklist_format.rs` | Shared JSON document shape for seed / feeds / custom |
| `custom_blocklist.rs` | User/project/env custom lists (highest priority) |
| `feed_cache.rs` | Runtime cache from `update-db` (`~/.cache/pkg-guard/`) |
| `update_db.rs` | Fetch remote feeds, merge with seed, write cache |
| `mod.rs` | Shared types: Ecosystem, AuditResult, TyposquatResult, … |

**Lookup order:** custom → feed cache → built-in seed.

Seed data lives under `data/blocklist/` in the repo and is **embedded at compile time** so the binary still works offline. Feeds and custom lists are **not** in source; they update without a rebuild.

## Data Flow

### MCP Tool Call

```
IDE → stdin (JSON-RPC) → server.rs → route to handler → core module → result → stdout (JSON-RPC) → IDE
```

### CLI Command

```
Terminal → clap parse → core module → result → stdout (pretty JSON)
```

### Container Audit

```
audit_package() → typosquat check → registry fetch → Docker pull → create container → start → wait → collect logs → parse JSON → cleanup → return AuditResult
```

## Concurrency Model

- **tokio** runtime for async I/O
- Registry calls are async (can be parallelized in future)
- Container operations are sequential per audit (one container per package)
- MCP server processes requests sequentially (single stdin stream)

## Error Handling Strategy

- **anyhow** for application-level errors with context
- **thiserror** available for typed errors if needed in future
- Graceful degradation: if Docker isn't available, audit still runs typosquat + metadata checks
- Registry failures are warnings, not fatal errors

## Binary Size Optimization

Release profile settings:
- `lto = true` — Link-Time Optimization
- `strip = true` — Strip debug symbols
- `codegen-units = 1` — Single codegen unit for better optimization
- `opt-level = 3` — Maximum optimization

Expected release binary: ~8-12MB (includes TLS via rustls, Docker API, HTTP client).
