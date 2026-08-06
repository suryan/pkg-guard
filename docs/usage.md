# Usage Guide

## Installation

### From Source

```bash
git clone <repo-url>
cd pkg-guard
cargo build --release
# Binary at: target/release/pkg-guard

# Optional: install to PATH
cp target/release/pkg-guard ~/.cargo/bin/
```

### Verify Installation

```bash
pkg-guard --version
pkg-guard --help
```

## Blocklist layers

Lookup order (first match wins):

1. **Custom** — operator-maintained (zero-day, no rebuild)  
2. **Feed cache** — from `pkg-guard update-db` (`~/.cache/pkg-guard/blocklist-cache.json`)  
3. **Seed** — embedded from `data/blocklist/seed.json` (offline default)

### Custom lists (fast response to new threats)

Locations (merged if several exist):

1. `PKG_GUARD_BLOCKLIST` — absolute path via environment variable  
2. `~/.config/pkg-guard/blocklist.json` (or `$XDG_CONFIG_HOME/pkg-guard/blocklist.json`)  
3. `.pkg-guard/blocklist.json` in the current working directory (project-local)

```bash
pkg-guard blocklist init
# Edit ~/.config/pkg-guard/blocklist.json — add names under python / npm / java
pkg-guard blocklist reload
pkg-guard blocklist status
pkg-guard check -e python -p that-new-malicious-name
# → blocklist_source: "custom"
```

Example file:

```json
{
  "version": 1,
  "python": ["that-new-malicious-name"],
  "npm": ["evil-typosquat"],
  "java": ["com.attacker:payload"]
}
```

Long-lived `pkg-guard serve` (MCP) **auto-reloads** custom files on mtime change.

### Feed cache (`update-db`)

```bash
# Seed-only refresh (always works offline)
pkg-guard update-db

# Merge remote feeds (JSON in the same schema as custom/seed)
pkg-guard update-db --feed https://example.com/team-blocklist.json
# or: export PKG_GUARD_FEED_URLS=https://a.json,https://b.json

pkg-guard blocklist status   # shows cache path, age, stale flag
```

If the cache is missing or older than **7 days**, `check` / audit recommendations
include a reminder to run `update-db`.

Default remote feeds are listed in `data/blocklist/default-feeds.json` (embedded)
and are used automatically when no `--feed` / `PKG_GUARD_FEED_URLS` is set.
Unreachable defaults soft-fail; the seed is always merged into the cache.

### OSV.dev version advisories

```bash
pkg-guard audit -e python -p jinja2 -v 2.4.1
# includes osv.advisories[] when the version is affected

pkg-guard scan -f package-lock.json
# blocklist hits + osv_findings for resolved versions (batch API, capped)
```

MCP: `blocklist_status`, `update_db` (optional `feeds: string[]`).

## CLI Usage

### Check a Package for Typosquatting

```bash
# Python
pkg-guard check -e python -p reqeusts
# Output: BLOCKED — package is on the known-malicious blocklist

pkg-guard check -e python -p requsts
# Output: WARNING — similar to 'requests' (distance: 1)

pkg-guard check -e python -p my-legitimate-package
# Output: OK — no typosquat patterns detected

# npm
pkg-guard check -e npm -p expresss
pkg-guard check -e npm -p lodash-js

# Java (use groupId:artifactId format)
pkg-guard check -e java -p "com.google.guava:guva"
```

### Scan Dependencies for Pinning Issues

```bash
# Python requirements
pkg-guard pin -f requirements.txt
pkg-guard pin -f requirements-dev.txt

# npm
pkg-guard pin -f package.json

# Java
pkg-guard pin -f pom.xml
pkg-guard pin -f build.gradle
```

Example output:
```json
{
  "file": "requirements.txt",
  "total_dependencies": 10,
  "pinned_count": 4,
  "unpinned_count": 6,
  "score": "4/10 pinned",
  "recommendation": "WARNING: 6 dependencies are not pinned to exact versions",
  "unpinned": [
    {
      "package": "Flask",
      "constraint": "Flask~=2.3.3",
      "issue": "uses range specifier instead of exact pin (==)"
    }
  ]
}
```

### Scan Lock Files for Malicious Packages

```bash
pkg-guard scan -f package-lock.json
pkg-guard scan -f yarn.lock
pkg-guard scan -f Pipfile.lock
```

Example output:
```json
{
  "file": "package-lock.json",
  "findings_count": 0,
  "status": "CLEAN — no known malicious packages found"
}
```

### Full Package Audit (Requires Docker)

```bash
# Python package
pkg-guard audit -e python -p requests -v 2.31.0

# npm package
pkg-guard audit -e npm -p express -v 4.18.2

# Java package
pkg-guard audit -e java -p "org.springframework:spring-core" -v 6.1.2
```

The audit performs:
1. Typosquat check
2. Registry metadata fetch
3. Container installation with monitoring
4. Aggregated risk assessment

Example output:
```json
{
  "status": "PASS",
  "package": "requests",
  "version": "2.31.0",
  "ecosystem": "python",
  "warnings": [],
  "recommendation": "SAFE to install — pin exact version with hash",
  "typosquat_check": {
    "is_suspicious": false,
    "is_blocklisted": false
  },
  "container_audit": {
    "install_success": true,
    "suspicious_network": false,
    "suspicious_filesystem": false,
    "suspicious_processes": false
  }
}
```

## MCP Server Mode

### Starting the Server

```bash
pkg-guard serve
```

The server reads JSON-RPC 2.0 messages from stdin and writes responses to stdout. Logs go to stderr.

### IDE Configuration (Kiro)

Add to `~/.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "pkg-guard": {
      "command": "/path/to/pkg-guard",
      "args": ["serve"],
      "disabled": false,
      "autoApprove": [
        "check_typosquat",
        "get_package_metadata",
        "pin_dependencies",
        "scan_lockfile"
      ]
    }
  }
}
```

### Available MCP Tools

#### `audit_package`

Full security audit with container isolation.

```json
{
  "ecosystem": "python",
  "package_name": "requests",
  "version": "2.31.0",
  "check_network": true,
  "check_filesystem": true,
  "check_processes": true
}
```

#### `check_typosquat`

Quick typosquat detection (no network, instant response).

```json
{
  "ecosystem": "npm",
  "package_name": "expresss"
}
```

#### `pin_dependencies`

Analyze a dependency file for version pinning compliance.

```json
{
  "file_path": "/path/to/requirements.txt",
  "generate_hashes": false,
  "fix_in_place": false
}
```

#### `scan_lockfile`

Check a lock file against the malicious package blocklist.

```json
{
  "file_path": "/path/to/package-lock.json"
}
```

#### `get_package_metadata`

Fetch registry metadata without installing.

```json
{
  "ecosystem": "python",
  "package_name": "flask",
  "version": "3.0.0"
}
```

## CI/CD Integration

### GitHub Actions

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install pkg-guard
        run: |
          curl -L https://github.com/<org>/pkg-guard/releases/latest/download/pkg-guard-linux-amd64 -o /usr/local/bin/pkg-guard
          chmod +x /usr/local/bin/pkg-guard

      - name: Check dependency pinning
        run: pkg-guard pin -f requirements.txt

      - name: Scan for malicious packages
        run: pkg-guard scan -f requirements.txt

      - name: Audit new dependencies
        run: pkg-guard audit -e python -p new-package -v 1.0.0
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Check if dependency files changed
if git diff --cached --name-only | grep -qE '(requirements.*\.txt|package\.json|pom\.xml)'; then
    echo "Scanning dependencies..."

    for file in $(git diff --cached --name-only | grep -E '(requirements.*\.txt|package\.json|pom\.xml)'); do
        result=$(pkg-guard pin -f "$file")
        unpinned=$(echo "$result" | jq '.unpinned_count')
        if [ "$unpinned" -gt 0 ]; then
            echo "WARNING: $file has $unpinned unpinned dependencies"
            echo "$result" | jq '.unpinned'
        fi
    done
fi
```

## Troubleshooting

### Docker not available

If Docker isn't installed or running, the `audit` command will report:
```json
{"error": "Cannot connect to Docker: ..."}
```

The audit still performs typosquat and metadata checks — only the container isolation is skipped.

### Package not found

If a package doesn't exist on the registry:
```json
{"status": "FAILED", "reason": "Package not found on registry"}
```

Verify the package name and version are correct.

### Timeout during audit

Container audits have a 120-second limit. If a package takes longer to install (large Java dependency trees), the audit times out and reports it as suspicious. For known-good large packages, use the non-container checks:

```bash
pkg-guard check -e java -p "org.springframework.boot:spring-boot"
```

### Verbose/Debug output

```bash
RUST_LOG=debug pkg-guard check -e python -p requests
RUST_LOG=trace pkg-guard audit -e npm -p express -v 4.18.2
```
