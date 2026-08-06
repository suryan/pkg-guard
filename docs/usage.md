# Usage Guide

## Installation

### From Source

```bash
git clone <repo-url>
cd pkg-guard
cargo build --release
# Binary at: target/release/pkg-guard

# Optional: install to PATH
make install                    # → ~/.local/bin/pkg-guard
# or: cp target/release/pkg-guard ~/.local/bin/
```

### Make shortcuts

```bash
make help          # list targets
make release       # optimized build
make install       # install to ~/.local/bin
make precommit     # fmt, clippy, tests, ≥90% coverage
make scan          # scan FILE=Cargo.lock
make dogfood       # scan this repo's Cargo.lock
make osv-update    # download local OSV dumps (ECOSYSTEMS=cargo optional)
make osv-status
```

### Verify Installation

```bash
pkg-guard --version
pkg-guard --help
```

## Blocklist layers

**No name denylist is embedded in the binary.** Lookup order (first match wins):

1. **Custom** — operator-maintained (zero-day)  
2. **Feed cache** — from `pkg-guard update-db` (`~/.cache/pkg-guard/blocklist-cache.json`)

Until you load a feed and/or custom list, name blocklisting is empty. Version advisories still work via local OSV dumps and/or the live OSV API (see below).


### Custom lists (fast response to new threats)

Locations (merged if several exist):

1. `PKG_GUARD_BLOCKLIST` — absolute path via environment variable  
2. `~/.config/pkg-guard/blocklist.json` (or `$XDG_CONFIG_HOME/pkg-guard/blocklist.json`)  
3. `.pkg-guard/blocklist.json` in the current working directory (project-local)

```bash
pkg-guard blocklist init
# Edit ~/.config/pkg-guard/blocklist.json — add names under python / npm / java / cargo
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
# Required: at least one feed URL (sample document in repo: data/blocklist/example-feed.json)
pkg-guard update-db --feed https://your-host/blocklist.json
# or: export PKG_GUARD_FEED_URLS=https://a.json,https://b.json

pkg-guard blocklist status   # shows cache path, age, empty flag
```

If no feed/custom list is loaded, `check` warns that the name blocklist is empty.
If the feed cache is older than **7 days**, recommendations remind you to refresh.

### OSV version advisories (local dump or live API)

`audit` and `scan` check resolved package **versions** for CVEs and `MAL-*` malware IDs.

**Scan does not download the OSV dump.** Refresh the local index yourself when you want newer data.

#### Recommended: local dump (offline / CI-friendly)

```bash
# Download per-ecosystem zips and build indexes under ~/.cache/pkg-guard/osv/
# Progress (size / % / speed) prints on stderr while downloading.
pkg-guard osv update
# or subset: pkg-guard osv update -e cargo
# or:        make osv-update ECOSYSTEMS=cargo,python
# or with feeds: pkg-guard update-db --feed https://… --osv

pkg-guard osv status
# or: make osv-status

# Force offline lookups (no api.osv.dev)
PKG_GUARD_OSV_MODE=local pkg-guard scan -f Cargo.lock
```

Sources (public GCS):  
`https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip`  
(`PyPI`, `npm`, `Maven`, `crates.io`). Override base URL with `PKG_GUARD_OSV_DUMP_BASE` for mirrors/tests.

| Ecosystem | Typical dump size (zip) | Notes |
|-----------|-------------------------|--------|
| cargo / crates.io | ~few MB | Fast to refresh |
| python / PyPI | ~tens of MB | |
| java / Maven | ~tens of MB | |
| npm | ~200MB+ | Slowest; skip with `-e` if unused |

Status treats the dump as **stale after 7 days** — re-run `osv update` to refresh. Nothing auto-updates on `scan`.

#### Lookup mode (`PKG_GUARD_OSV_MODE`)

| Mode | Behavior |
|------|----------|
| `auto` (default) | Use local index when present for that ecosystem; else live [api.osv.dev](https://osv.dev) |
| `local` | Local dump only (errors if index missing) |
| `online` | Live API only (previous default behaviour) |

```bash
# After osv update, auto uses the dump without extra flags
pkg-guard scan -f package-lock.json
pkg-guard audit -e python -p jinja2 -v 2.4.1
# → osv.advisories[] / osv_findings; source may be "local" or "online"
```

Every resolved package in the lockfile is OSV-checked (no package-count cap). Large online scans may take longer; prefer a local dump (`osv update`) for big trees.

MCP: `osv_status`, `osv_update` (optional `ecosystems: string[]`), plus `blocklist_status`, `update_db` (`feeds`, optional `osv: true`).

## Transparent package-manager shims

`pkg-guard` can **look like** `pip` / `npm` / `npx` / `uvx` / `uv` / `cargo`
(multicall via symlink). On install-like or package-run commands it runs policy
checks, then `exec`s the real tool.

### MCP launchers (`uvx` / `npx`) — the real gap

Many MCP servers start as:

```json
"command": "uvx",
"args": ["mcp-atlassian==0.23.0"]
```

or:

```json
"command": "npx",
"args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2"]
```

That is **not** a lockfile scan. `uvx`/`npx` resolve the named package **and**
all of its **transitive dependencies** from the registry. A compromise can live
in a dep you never typed.

**What shims do today**

| Launcher | Gated |
|----------|--------|
| `uvx pkg==ver` / `uv tool run …` | Top-level package name (+ version OSV if pinned) |
| `npx -y pkg@ver` / `pnpm dlx` / `yarn dlx` | Top-level package name (+ version if present) |
| `pip install` / `npm install` / `cargo add` | As before |

**What they do *not* do yet**

- Fully resolve and audit the **entire** transitive tree *before* `uvx`/`npx` runs
- Stop absolute-path launches (`/home/…/.local/bin/uvx` if not shimmed first on `PATH`)

**Practical controls**

1. Install shims so `uvx`/`npx` on `PATH` hit pkg-guard first  
2. **Pin versions** in MCP config (`pkg==1.2.3`, `pkg@1.2.3`) so OSV can match  
3. Keep **local OSV dumps** fresh (`pkg-guard osv update`)  
4. Prefer custom/feed **blocklists** for known-bad names  
5. For high-trust MCP tools, prefer a **vendored/binary** install over floating `uvx`/`npx`  

### Issues with transparent calls (and mitigations)

| Issue | Mitigation |
|-------|------------|
| Recursion (`pip` → pkg-guard → `pip` → …) | Real binary resolution **skips this executable**; override with `PKG_GUARD_REAL_PIP` etc. |
| Bypass via `/usr/bin/pip` or absolute path | Shims only work when early on `PATH` |
| MCP `uvx`/`npx` transitive deps | Gate top-level package; pin versions; OSV + blocklists; residual tree risk |
| Incomplete CLI parsing | Common install/run forms gated; exotic URLs/paths pass through or skip |
| Slow gates | Blocklist + OSV when version known; **no** Docker audit on every install |

### Install shims

```bash
cargo build --release
# or: make install
pkg-guard shim install --dir ~/.local/bin \
  --tools pip,pip3,npm,npx,uvx,uv,cargo
# ensure ~/.local/bin is before /usr/bin on PATH
pkg-guard shim status

# Modes
export PKG_GUARD_SHIM_MODE=enforce   # default: block bad installs / bad MCP packages
export PKG_GUARD_SHIM_MODE=warn      # print warning, still run
export PKG_GUARD_SHIM_MODE=off       # fully transparent

# Point at the real tools if auto-detect fails
export PKG_GUARD_REAL_PIP=/usr/bin/pip3
export PKG_GUARD_REAL_NPM=/usr/bin/npm
export PKG_GUARD_REAL_NPX=/usr/bin/npx
export PKG_GUARD_REAL_UVX=$HOME/.local/bin/uvx   # real binary, not the shim
export PKG_GUARD_REAL_CARGO=$HOME/.cargo/bin/cargo
```

Then:

```bash
pip install requests==2.31.0     # gated, then real pip
pip install reqeusts             # BLOCKED if on feed/custom blocklist
npm install lodash@4.17.21
npx -y left-pad@1.3.0            # gated (top-level)
uvx mcp-atlassian==0.23.0        # gated (top-level MCP package)
cargo add serde@1.0
pip list                         # pass-through, no gate
```

## CLI Usage

### Check a Package for Typosquatting

```bash
# Python
pkg-guard check -e python -p reqeusts
# Output: BLOCKED if on custom list or feed cache (no denylist in the binary)

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

Checks **name blocklists** (custom + feed cache) and **OSV version advisories** (local dump and/or live API).

```bash
pkg-guard scan -f package-lock.json
pkg-guard scan -f yarn.lock
pkg-guard scan -f Pipfile.lock
pkg-guard scan -f Cargo.lock
# make scan FILE=Cargo.lock
```

Example output:
```json
{
  "file": "Cargo.lock",
  "packages_total": 225,
  "packages_blocklist_checked": 225,
  "packages_osv_checked": 225,
  "osv_mode": "auto",
  "osv_backend": "local",
  "findings_count": 0,
  "osv_count": 0,
  "status": "CLEAN — scanned 225 package(s), OSV-checked 225 (OSV=local dump); no known malicious packages or OSV advisories found"
}
```

`packages_total` / `packages_osv_checked` are how many deps were found and OSV-checked (all of them). `osv_backend` is `local` (disk dump) or `online` (api.osv.dev).
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
3. OSV version advisories (local dump and/or live API)
4. Container installation with monitoring (when Docker is available)
5. Aggregated risk assessment

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
        "scan_lockfile",
        "blocklist_status",
        "osv_status"
      ]
    }
  }
}
```

Restart the MCP host after upgrading the binary so it picks up new tools.

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

Check a lock file against custom/feed name blocklists **and** OSV (local dump / live API).

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

#### `audit_project`

Walk a project tree for manifests/lockfiles (pins + name blocklist).

```json
{
  "project_path": "/path/to/project"
}
```

#### `blocklist_status`

Custom list paths, feed-cache snapshot, and OSV dump status.

#### `update_db`

Refresh feed cache from URLs. Optional `osv: true` also runs an OSV dump update.

```json
{
  "feeds": ["https://your-host/blocklist.json"],
  "osv": false
}
```

#### `osv_status`

Local OSV dump path, age, ecosystems, and `PKG_GUARD_OSV_MODE`.

#### `osv_update`

Download OSV ecosystem dumps and rebuild indexes (can take minutes; npm is large).

```json
{
  "ecosystems": ["cargo", "python"]
}
```

Omit `ecosystems` to update all defaults (python, npm, java, cargo).

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

      # Optional offline OSV: cache ~/.cache/pkg-guard/osv across runs
      - name: Refresh local OSV dump
        run: pkg-guard osv update -e cargo,python
        # or full: pkg-guard osv update

      - name: Check dependency pinning
        run: pkg-guard pin -f requirements.txt

      - name: Scan for malicious packages (local OSV)
        env:
          PKG_GUARD_OSV_MODE: local
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

## Environment variables

| Variable | Purpose |
|----------|---------|
| `PKG_GUARD_BLOCKLIST` | Extra custom blocklist JSON path |
| `PKG_GUARD_FEED_URLS` | Comma-separated feed URLs for `update-db` |
| `PKG_GUARD_CACHE_DIR` | Cache root (feed + OSV indexes; default `~/.cache/pkg-guard`) |
| `PKG_GUARD_OSV_MODE` | `auto` \| `local` \| `online` (OSV lookup) |
| `PKG_GUARD_OSV_DUMP_BASE` | Mirror base for OSV zips (default Google GCS bucket) |
| `PKG_GUARD_SHIM_MODE` | `enforce` \| `warn` \| `off` |
| `PKG_GUARD_REAL_<TOOL>` | Absolute path to real `pip` / `npm` / `cargo` / … |
| `RUST_LOG` | Tracing filter (`debug`, `info`, …) |

## Troubleshooting

### Docker not available

If Docker isn't installed or running, container steps in `audit` fail or degrade; typosquat, metadata, and OSV still run.

### Local OSV index missing

```text
Local OSV index missing for crates.io … Run: pkg-guard osv update
```

With `PKG_GUARD_OSV_MODE=local`, update dumps first. With `auto`, the tool falls back to the live API when the index is missing.

### OSV dump looks stale

```bash
pkg-guard osv status    # age_days, stale flag
pkg-guard osv update    # refresh
```

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
RUST_LOG=info pkg-guard osv update -e cargo
RUST_LOG=trace pkg-guard audit -e npm -p express -v 4.18.2
```
