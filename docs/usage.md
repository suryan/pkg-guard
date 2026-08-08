# Usage Guide

## Installation

pkg-guard is a single Rust binary. Prefer **install from source** on each machine
(no GitHub release artifacts to maintain). Supported: **macOS**, **Linux**, **WSL2**.

### One-liner (recommended)

```bash
# Binary + global MCP shims (uvx/uv/npx) + shell PATH integration
curl -fsSL https://raw.githubusercontent.com/suryan/pkg-guard/master/scripts/install.sh \
  | bash -s -- --with-shims --yes
```

What it does:

1. Ensures a Rust toolchain (`rustup` if `cargo` is missing)
2. Clones/updates the repo under `~/.local/src/pkg-guard` (override with `--dir`)
3. `cargo build --release`
4. Installs to `~/.local/bin/pkg-guard` (override with `--prefix`)
5. With `--with-shims`: runs `scripts/setup-user.sh`
   - multicall links for **`uvx`, `uv`, `npx`** only (MCP launchers)
   - writes `~/.config/pkg-guard/shim.env`
   - sources it from `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.zprofile` (idempotent)
   - writes per-project template `~/.config/pkg-guard/project-shims.example.env`

```bash
# Common options
bash scripts/install.sh --help
bash scripts/install.sh --prefix ~/.local --with-shims --yes
bash scripts/install.sh --with-shims --with-osv --yes   # also download OSV dumps
bash scripts/install.sh --with-shims --shims all        # full global tool set
bash scripts/install.sh --ref master
bash scripts/install.sh --local --with-shims            # current clone only
PKG_GUARD_PREFIX=/usr/local sudo -E bash scripts/install.sh --yes   # system-wide (careful)
```

| Variable / flag | Default | Meaning |
|-----------------|---------|---------|
| `--prefix` / `PKG_GUARD_PREFIX` | `~/.local` | Binary at `$PREFIX/bin/pkg-guard` |
| `--ref` / `PKG_GUARD_REF` | `master` | Git branch, tag, or commit |
| `--repo` / `PKG_GUARD_REPO` | this GitHub repo | Clone URL |
| `--dir` / `PKG_GUARD_DIR` | `~/.local/src/pkg-guard` | Checkout path |
| `--with-shims` | off | MCP shims + `shim.env` + shell rc (see `setup-user.sh`) |
| `--shims` | `mcp` | With shims: `mcp` \| `all` \| `uvx,npx,…` |
| `--no-shell-rc` | off | Install shims + env file only; do not edit rc files |
| `--with-osv` | off | Run `pkg-guard osv update` after install (large) |
| `--yes` | off | Non-interactive rustup install |

**Requirements:** `curl` + `git`, C linker (`build-essential` on Debian/Ubuntu,
Xcode CLT on macOS: `xcode-select --install`), network for crates.io.

### `cargo install` (Rust toolchain already present)

```bash
cargo install --git https://github.com/suryan/pkg-guard --locked
./scripts/setup-user.sh    # shims + shell integration (from a clone)
```

### From a local clone

```bash
git clone https://github.com/suryan/pkg-guard.git
cd pkg-guard
./scripts/install.sh --local --with-shims
# or stepwise:
make setup-user                 # release binary + MCP shims + shell rc
# make shim-install SHIM_TOOLS=all
```

### Make shortcuts

```bash
make help          # list targets
make release       # optimized build
make install       # install binary to ~/.local/bin
make setup-user    # binary + MCP shims + shim.env + shell rc
make shim-install  # SHIM_TOOLS=uvx,uv,npx (or mcp / all)
make precommit     # fmt, clippy, tests, ≥90% coverage
make scan          # scan FILE=Cargo.lock
make dogfood       # scan this repo's Cargo.lock
make osv-update    # download local OSV dumps (ECOSYSTEMS=cargo optional)
make osv-status
```

### Verify installation

```bash
pkg-guard --version
pkg-guard --help
# after --with-shims / setup-user (new shell):
which -a uvx npx pip cargo
pkg-guard shim status --tools uvx,uv,npx
```

If `pkg-guard` is not found, add `~/.local/bin` to `PATH`.

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
# Progress on stderr. Skips ecosystems already matching remote (ETag/Last-Modified).
pkg-guard osv update
pkg-guard osv update --force          # re-download even if latest
# or subset: pkg-guard osv update -e cargo
# or:        make osv-update ECOSYSTEMS=cargo,python

pkg-guard osv status                  # local state + remote up_to_date per ecosystem
# or: make osv-status

# Scan auto-refreshes dumps when needed (skip with PKG_GUARD_OSV_AUTO_UPDATE=0)
pkg-guard scan -f Cargo.lock

# Force offline lookups (no api.osv.dev)
PKG_GUARD_OSV_MODE=local pkg-guard scan -f Cargo.lock
```

**How “already latest” is detected:** on `osv update` (and scan auto-refresh), pkg-guard
sends HTTP `HEAD` to each dump zip and compares `ETag` / `Last-Modified` / size with values
stored in `~/.cache/pkg-guard/osv/meta.json`. Match → **skip download** (`action:
skipped_up_to_date`). Use `--force` to ignore that.

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
| `uvx pkg==ver` / `uv tool run …` | Top-level + **all** transitive runtime deps (via registry metadata); blocklist + OSV when version known |
| `npx -y pkg@ver` / `pnpm dlx` / `yarn dlx` | Same (npm registry deps) |
| `pip install` / `npm install` / `cargo add` | As before (install line packages / files) |

Transitive resolve walks the full runtime tree (cycle-safe). Not a full solver
(optional extras / complex ranges may be incomplete). Disable with
`PKG_GUARD_SHIM_TRANSITIVE=0`.

**Residual gaps**

- Optional/dev extras and complex version ranges may be incomplete  
- Absolute-path launches bypass shims if not first on `PATH`  

**Practical controls**

1. Follow **[Best setup](#best-setup-recommended)** (shim dir first on PATH; leave reals in place)  
2. **Pin versions** in MCP config (`pkg==1.2.3`, `pkg@1.2.3`) so OSV can match  
3. Keep **local OSV dumps** fresh (scan auto-refreshes; or `pkg-guard osv update`)  
4. Prefer custom/feed **blocklists** for known-bad names  
5. For high-trust MCP tools, prefer a **vendored/binary** install over floating `uvx`/`npx`  
6. MCP hosts: set PATH in the server env (do not assume bashrc)  

### Issues with transparent calls (and mitigations)

| Issue | Mitigation |
|-------|------------|
| Recursion (`pip` → pkg-guard → `pip` → …) | PATH walk **skips pkg-guard shims**; optional `PKG_GUARD_REAL_*` override |
| Bypass via `/usr/bin/pip` or absolute path | Shims only work when shim dir is early on `PATH` |
| Updaters overwrite tools | Leave reals in place; only shim dir is owned by pkg-guard |
| MCP `uvx`/`npx` transitive deps | Gate top-level package; pin versions; OSV + blocklists; residual tree risk |
| Incomplete CLI parsing | Common install/run forms gated; exotic URLs/paths pass through or skip |
| Slow gates | Blocklist + OSV when version known; **no** Docker audit on every install |

### Best setup (recommended)

**Policy:** global shims cover **MCP launchers only** (`uvx`, `uv`, `npx`).
`pip` / `npm` / `cargo` installs are a **per-project** choice (direnv / project env),
so each repo can decide enforce vs warn and which tools to gate.

**Rule:** put shims in a **dedicated directory that is first on `PATH`**.
Leave real package managers where their installers put them. Do **not** move,
copy, or rename real `uv` / `uvx` / `npx` / `pip` into a pkg-guard tree.

```text
PATH order (left = first):

  ~/.local/share/pkg-guard/shims/     ← pkg-guard owns this (global)
      uv  →  ~/.local/bin/pkg-guard
      uvx →  ~/.local/bin/pkg-guard
      npx →  ~/.local/bin/pkg-guard
      (no pip/npm/cargo here by default)

  ~/.local/bin/                       ← real uv / uvx (self-update OK)
  ~/.nvm/.../bin/                     ← real npx / npm
  ~/.cargo/bin/                       ← real cargo
  …
```

How a call works:

1. Shell finds `uvx` in the **shim dir** → runs `pkg-guard`
2. pkg-guard applies policy (blocklist, OSV, optional transitive expand)
3. Resolver walks `PATH`, **skips** any pkg-guard shim, finds the **real** tool
4. `exec` real tool with the original args

#### Why not put shims in `~/.local/bin`?

`uv` / `uvx` also install into `~/.local/bin`. One directory can only have one
file named `uv`. Installing a shim there **overwrites** the real binary (or
forces you to relocate it, which freezes upgrades). A separate shim directory
avoids that.

#### Step-by-step (automated — preferred)

Works the same on **macOS (zsh)** and **Linux (bash/zsh)**:

```bash
# From a clone, after the binary exists — or use install.sh --with-shims
./scripts/setup-user.sh
# equivalent: make setup-user
# options:    ./scripts/setup-user.sh --tools all
#             ./scripts/setup-user.sh --no-shell-rc
```

That is idempotent: re-running will not duplicate shell rc blocks.

#### Step-by-step (manual)

```bash
# 1) Binary
make install
# → ~/.local/bin/pkg-guard

# 2) Global MCP shims only
pkg-guard shim install --tools uvx,uv,npx
# → ~/.local/share/pkg-guard/shims/{uvx,uv,npx}
# full set (usually avoid globally):  --tools pip,pip3,npm,npx,uvx,uv,cargo

# 3) PATH via shared env file
mkdir -p ~/.config/pkg-guard
cat > ~/.config/pkg-guard/shim.env <<'EOF'
export PATH="${HOME}/.local/share/pkg-guard/shims:${PATH}"
export PKG_GUARD_SHIM_MODE="${PKG_GUARD_SHIM_MODE:-enforce}"
EOF

# 4–5) Interactive + login shells (bash and zsh)
for f in ~/.bashrc ~/.zshrc ~/.profile ~/.zprofile; do
  grep -q 'pkg-guard/shim.env' "$f" 2>/dev/null && continue
  printf '\n# >>> pkg-guard shims >>>\n[ -f "$HOME/.config/pkg-guard/shim.env" ] && . "$HOME/.config/pkg-guard/shim.env"\n# <<< pkg-guard shims <<<\n' >> "$f"
done

# 6) New shell (or: source ~/.config/pkg-guard/shim.env)
# 7) Verify
pkg-guard shim status --tools uvx,uv,npx
which -a uv uvx npx pip cargo
# uvx/npx first hit = …/pkg-guard/shims/… ; pip/cargo = real tools
```

#### Per-project shims (pip / npm / cargo)

```bash
# In the repo
pkg-guard shim install -d .pkg-guard/shims --tools pip,pip3,npm,cargo

# direnv .envrc
PATH_add .pkg-guard/shims
export PKG_GUARD_SHIM_MODE="${PKG_GUARD_SHIM_MODE:-enforce}"
# direnv allow
```

See also `~/.config/pkg-guard/project-shims.example.env` after `setup-user.sh`.

#### MCP / IDE hosts

GUI apps and MCP launchers often **do not** load `~/.bashrc` or `~/.profile`.
Give them the same env explicitly, for example:

```json
{
  "env": {
    "PATH": "/home/YOU/.local/share/pkg-guard/shims:/home/YOU/.local/bin:/usr/bin",
    "PKG_GUARD_SHIM_MODE": "enforce"
  }
}
```

Or start the host from a shell that already sourced `shim.env`. If MCP
config uses an **absolute** path to real `uvx`/`npx`, the gate is skipped —
prefer the bare command name so `PATH` resolves the shim.

#### Modes

| Mode | Env | Behavior |
|------|-----|----------|
| **enforce** (default) | `PKG_GUARD_SHIM_MODE=enforce` | Block policy failures (exit 2) |
| **warn** | `PKG_GUARD_SHIM_MODE=warn` | Print warning, still run real tool |
| **off** | `PKG_GUARD_SHIM_MODE=off` | Fully transparent (no checks) |

#### Optional overrides (usually unnecessary)

Only if PATH lookup fails (exotic layouts, missing real on PATH):

```bash
export PKG_GUARD_REAL_UVX=$HOME/.local/bin/uvx
export PKG_GUARD_REAL_NPX=$HOME/.nvm/versions/node/v20.19.2/bin/npx
# or any: PKG_GUARD_REAL_<TOOL>=/absolute/path
```

Prefer fixing PATH order over pinning `REAL_*` — pinned paths go stale when
you upgrade Node / move installs.

#### After `uv` / Node updates

- Official `uv` installers and `uv self update` rewrite **`~/.local/bin`** —
  that is fine; shims are elsewhere.
- nvm / new Node: real `npx` moves under a new version dir; as long as that
  dir is still on PATH after the shim dir, resolution still works.
- If an installer ever drops files into the **shim** dir, re-run
  `pkg-guard shim install`.
- Health check anytime: `pkg-guard shim status` and `which -a uvx`.

#### Anti-patterns (avoid)

| Don't | Why |
|-------|-----|
| `shim install --dir ~/.local/bin` when uv lives there | Overwrites real `uv`/`uvx` |
| Move reals into `~/.local/lib/pkg-guard/real/` | Freezes upgrades; not needed |
| Rely only on bashrc for MCP | Hosts often skip shell profiles |
| Absolute `/path/to/real/uvx` in MCP config | Bypasses the gate |
| `PKG_GUARD_REAL_*` as the primary mechanism | PATH order is the design |

#### Smoke tests

```bash
# Pass-through (no package gate)
uv --version
uvx --help
npx --version

# Gated package runs (blocklist + OSV when versioned; may expand transitive deps)
uvx ruff==0.9.0 --version
npx -y cowsay@1.5.0 --version

pip install requests==2.31.0     # gated, then real pip
pip list                         # pass-through
```

#### Uninstall shims

```bash
pkg-guard shim uninstall          # removes default dir links only
# real uv/npx/pip are untouched
# remove PATH line from bashrc/profile/shim.env when done
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
| `PKG_GUARD_OSV_AUTO_UPDATE` | On scan, refresh dumps if remote changed (default **on**; set `0` to disable) |
| `PKG_GUARD_OSV_DUMP_BASE` | Mirror base for OSV zips (default Google GCS bucket) |
| `PKG_GUARD_SHIM_MODE` | `enforce` \| `warn` \| `off` (default enforce) |
| `PKG_GUARD_SHIM_DIR` | Default dir for `shim install` (`~/.local/share/pkg-guard/shims`) |
| `PKG_GUARD_SHIM_TRANSITIVE` | Expand uvx/npx deps for gate (default **on**; set `0` to disable) |
| `PKG_GUARD_REAL_<TOOL>` | Optional absolute path to real tool; prefer PATH order instead |
| `RUST_LOG` | Tracing filter (`debug`, `info`, …) |

## Troubleshooting

### Docker not available

If Docker isn't installed or running, container steps in `audit` fail or degrade; typosquat, metadata, and OSV still run.

### Local OSV index missing

```text
Local OSV index missing for crates.io … Run: pkg-guard osv update
```

With `PKG_GUARD_OSV_MODE=local`, update dumps first. With `auto`, the tool falls back to the live API when the index is missing.

### Shims not gating / real tool runs first

```bash
which -a uvx
# Bad:  first line is ~/.local/bin/uvx  (or nvm) with no shim ahead
# Good: first line is ~/.local/share/pkg-guard/shims/uvx
```

1. Confirm shims exist: `ls ~/.local/share/pkg-guard/shims`
2. Prepend shim dir on PATH (source `~/.config/pkg-guard/shim.env`)
3. If login shell still puts `~/.local/bin` first, source `shim.env` **last** in `~/.profile`
4. MCP/IDE: set PATH in the host env (they often skip bashrc)
5. `pkg-guard shim status` — each tool should show `real_binary` and `shim_present: true`

### could not find real 'uvx' on PATH

Shim ran but no second `uvx` exists after skipping shims. Install real `uv`
(normal location), ensure its directory is on PATH **after** the shim dir, or
set `PKG_GUARD_REAL_UVX` temporarily.

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
