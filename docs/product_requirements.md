# Product Requirements

## Problem Statement

Software supply chain attacks are one of the fastest-growing threat vectors. Developers routinely install packages from public registries (PyPI, npm, Maven Central) without verifying their legitimacy. Common attack patterns include:

- **Typosquatting** — Registering names similar to popular packages (e.g., `reqeusts` instead of `requests`)
- **Dependency confusion** — Publishing internal package names to public registries
- **Account hijacking** — Compromising maintainer accounts to push malicious updates
- **Malicious install scripts** — Executing arbitrary code during `npm install` or `pip install`
- **Star-jacking** — Pointing a package's repository URL to a legitimate project to appear trustworthy

These attacks succeed because there is no automated gate between "developer types a package name" and "code runs on their machine."

## Goals

1. **Prevent installation of known malicious packages** by maintaining and checking against a curated blocklist
2. **Detect typosquatting attempts** before packages are installed using algorithmic similarity matching
3. **Audit package behavior in isolation** by running installations in disposable containers with security monitoring
4. **Enforce version pinning** across dependency files to prevent silent upgrades to compromised versions
5. **Integrate seamlessly into developer workflows** via MCP (IDE) and CLI (terminal/CI) interfaces
6. **Zero-friction deployment** — single binary, no runtime dependencies beyond optional Docker

## Target Users

- **Individual developers** who want automated package vetting in their IDE
- **Security-conscious teams** who need supply chain governance in CI/CD
- **Platform engineers** who build internal developer tools and want to embed package security checks

## Functional Requirements

### FR-1: Typosquat Detection

| ID | Requirement |
|----|-------------|
| FR-1.1 | Detect package names within Levenshtein distance ≤ 2 of popular packages |
| FR-1.2 | Detect homoglyph substitutions (l/1, O/0, I/l) |
| FR-1.3 | Detect common suffix/prefix tricks (-js, -py, -utils, version numbers) |
| FR-1.4 | Detect separator variations (hyphen, underscore, dot, none) |
| FR-1.5 | Maintain a database of 50+ popular packages per ecosystem |
| FR-1.6 | Return similarity scores and the closest legitimate package name |
| FR-1.7 | Support Python, npm, and Java ecosystems |

### FR-2: Blocklist Enforcement

| ID | Requirement |
|----|-------------|
| FR-2.1 | Maintain an embedded blocklist of known malicious packages |
| FR-2.2 | Check packages against blocklist before any installation |
| FR-2.3 | Blocklist must be updatable via source code change and rebuild |
| FR-2.4 | Cover all three ecosystems (Python, npm, Java) |
| FR-2.5 | Include known hijacked package versions (event-stream, ua-parser-js, log4j) |

### FR-3: Container Auditing

| ID | Requirement |
|----|-------------|
| FR-3.1 | Install packages in isolated Docker containers |
| FR-3.2 | Monitor network activity during installation |
| FR-3.3 | Monitor filesystem writes outside expected paths |
| FR-3.4 | Monitor process spawning for reverse shells and miners |
| FR-3.5 | Enforce resource limits (memory, PIDs) to prevent DoS |
| FR-3.6 | Timeout after 120 seconds with automatic cleanup |
| FR-3.7 | Return structured JSON results from container audit |
| FR-3.8 | Gracefully degrade when Docker is unavailable |

### FR-4: Dependency Pinning Analysis

| ID | Requirement |
|----|-------------|
| FR-4.1 | Parse requirements.txt and detect unpinned versions (>=, ~=, bare) |
| FR-4.2 | Parse package.json and detect range specifiers (^, ~, *, latest) |
| FR-4.3 | Parse pom.xml and detect dynamic versions (LATEST, RELEASE, SNAPSHOT, ${}) |
| FR-4.4 | Parse build.gradle and detect dynamic version references |
| FR-4.5 | Report pinning score (X/Y pinned) |
| FR-4.6 | Provide fix suggestions for each ecosystem |

### FR-5: Lock File Scanning

| ID | Requirement |
|----|-------------|
| FR-5.1 | Scan package-lock.json for blocklisted packages |
| FR-5.2 | Scan yarn.lock for blocklisted packages |
| FR-5.3 | Scan Pipfile.lock for blocklisted packages |
| FR-5.4 | Scan requirements.txt (when used as a lock file) for blocklisted packages |
| FR-5.5 | Report severity level (CRITICAL for blocklisted packages) |

### FR-6: Registry Metadata

| ID | Requirement |
|----|-------------|
| FR-6.1 | Fetch metadata from PyPI without installing |
| FR-6.2 | Fetch metadata from npm without installing |
| FR-6.3 | Fetch metadata from Maven Central without installing |
| FR-6.4 | Detect npm packages with install scripts (preinstall/postinstall) |
| FR-6.5 | Return maintainer info, dependencies, and project URLs |

### FR-7: Interfaces

| ID | Requirement |
|----|-------------|
| FR-7.1 | MCP server mode via `pkg-guard serve` (JSON-RPC over stdio) |
| FR-7.2 | CLI mode with subcommands: audit, check, pin, scan |
| FR-7.3 | All outputs in structured JSON |
| FR-7.4 | MCP protocol version 2024-11-05 compliance |
| FR-7.5 | Tool definitions with JSON Schema for input validation |

## Non-Functional Requirements

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-1 | Typosquat check latency | < 5ms (no network) |
| NFR-2 | Registry metadata fetch | < 2s per package |
| NFR-3 | Container audit duration | < 120s |
| NFR-4 | Binary size (release) | < 15MB |
| NFR-5 | Memory usage (MCP server idle) | < 10MB RSS |
| NFR-6 | Startup time | < 100ms |
| NFR-7 | Zero runtime dependencies | No Python/Node/Java needed |
| NFR-8 | Cross-platform | Linux, macOS (Docker for audit) |

## Out of Scope (v1)

- Real-time package registry monitoring / webhook integration
- Automatic blocklist updates from external feeds (requires rebuild)
- Dependency confusion detection (requires private registry knowledge)
- SBOM generation (Software Bill of Materials)
- Integration with Snyk/Dependabot/Renovate
- Windows container auditing
- GUI / web interface

## Success Metrics

- Blocks 100% of packages on the embedded blocklist
- Detects typosquats within edit distance 2 with zero false negatives on the popular package list
- Container audit catches network exfiltration and filesystem abuse in test scenarios
- Full audit completes in under 2 minutes per package
- Seamless MCP integration with no user-visible latency for non-audit tools
