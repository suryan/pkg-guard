#!/usr/bin/env bash
# pkg-guard install-from-source (macOS + Linux / WSL2)
#
# Builds and installs a release binary on the local machine. No GitHub release
# artifacts required — only git, a C toolchain, and Rust (rustup is bootstrapped
# if cargo is missing).
#
# One-liner (from GitHub):
#   curl -fsSL https://raw.githubusercontent.com/suryan/pkg-guard/master/scripts/install.sh | bash
#
# Recommended (binary + MCP shims + shell PATH):
#   curl -fsSL …/install.sh | bash -s -- --with-shims --yes
#
# From a local clone:
#   ./scripts/install.sh --local --with-shims
#   ./scripts/install.sh --ref v0.5.0 --with-shims --with-osv
#
# Environment (optional):
#   PKG_GUARD_REPO     git URL (default: https://github.com/suryan/pkg-guard.git)
#   PKG_GUARD_REF      branch/tag/commit (default: master)
#   PKG_GUARD_PREFIX   install prefix (default: $HOME/.local) → bin/pkg-guard
#   PKG_GUARD_DIR      source checkout dir (default: $HOME/.local/src/pkg-guard)
#   PKG_GUARD_SHIM_DIR override shim directory
#   CARGO_HOME / RUSTUP_HOME  standard rustup vars
#
# Exit codes: 0 success, 1 user/env error, 2 build/install failure

set -euo pipefail

REPO_DEFAULT="https://github.com/suryan/pkg-guard.git"
REPO="${PKG_GUARD_REPO:-$REPO_DEFAULT}"
REF="${PKG_GUARD_REF:-master}"
PREFIX="${PKG_GUARD_PREFIX:-${PREFIX:-$HOME/.local}}"
SRC_DIR="${PKG_GUARD_DIR:-$HOME/.local/src/pkg-guard}"
WITH_SHIMS=0
WITH_OSV=0
SHIM_TOOLS="mcp"   # mcp | all | comma-list (see setup-user.sh)
NO_SHELL_RC=0
YES=0
KEEP_SRC=1
LOCAL_ONLY=0

usage() {
  cat <<'EOF'
Usage: install.sh [options]

  --prefix DIR     Install prefix (binary → DIR/bin/pkg-guard). Default: ~/.local
  --ref REF        Git branch, tag, or commit. Default: master
  --repo URL       Git remote URL
  --dir DIR        Source checkout directory. Default: ~/.local/src/pkg-guard
  --with-shims     MCP shims (uvx,uv,npx) + shim.env + shell rc (macOS/Linux)
  --shims LIST     With --with-shims: mcp (default) | all | uvx,npx,…
  --no-shell-rc    With --with-shims: install links + shim.env, do not edit rc
  --with-osv       After install, run: pkg-guard osv update (large; npm ~200MB+)
  --no-keep-src    Remove the checkout after a successful install
  --local          Build the repo containing this script (no clone/fetch)
  --yes            Non-interactive (auto-install rustup if needed)
  -h, --help       Show this help

Examples:
  # Recommended first-time setup
  curl -fsSL https://raw.githubusercontent.com/suryan/pkg-guard/master/scripts/install.sh \
    | bash -s -- --with-shims --yes

  ./scripts/install.sh --local --with-shims
  ./scripts/install.sh --local --with-shims --shims all
  PKG_GUARD_REF=v0.5.0 ./scripts/install.sh --yes --with-shims --with-osv

Shims: global default is MCP-only (uvx, uv, npx). Gate pip/npm/cargo per project
(see docs/usage.md and ~/.config/pkg-guard/project-shims.example.env).
EOF
}

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'warn: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# ─── args ────────────────────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)      PREFIX="${2:-}"; shift 2 ;;
    --prefix=*)    PREFIX="${1#*=}"; shift ;;
    --ref)         REF="${2:-}"; shift 2 ;;
    --ref=*)       REF="${1#*=}"; shift ;;
    --repo)        REPO="${2:-}"; shift 2 ;;
    --repo=*)      REPO="${1#*=}"; shift ;;
    --dir)         SRC_DIR="${2:-}"; shift 2 ;;
    --dir=*)       SRC_DIR="${1#*=}"; shift ;;
    --with-shims)  WITH_SHIMS=1; shift ;;
    --shims)       SHIM_TOOLS="${2:-}"; WITH_SHIMS=1; shift 2 ;;
    --shims=*)     SHIM_TOOLS="${1#*=}"; WITH_SHIMS=1; shift ;;
    --no-shell-rc) NO_SHELL_RC=1; shift ;;
    --with-osv)    WITH_OSV=1; shift ;;
    --no-keep-src) KEEP_SRC=0; shift ;;
    --local)       LOCAL_ONLY=1; shift ;;
    --yes|-y)      YES=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             die "unknown option: $1 (try --help)" ;;
  esac
done

BINDIR="${PREFIX}/bin"
BIN="${BINDIR}/pkg-guard"

# ─── platform ────────────────────────────────────────────────────────────────

OS="$(uname -s 2>/dev/null || echo unknown)"
ARCH="$(uname -m 2>/dev/null || echo unknown)"
log "platform: ${OS}/${ARCH}"

case "$OS" in
  Linux|Darwin) ;;
  MINGW*|MSYS*|CYGWIN*)
    die "Windows native shell is not supported yet. Use WSL2, then re-run this script."
    ;;
  *)
    warn "untested OS '${OS}' — continuing; need a Unix-like environment with cargo"
    ;;
esac

# ─── rust toolchain ──────────────────────────────────────────────────────────

ensure_rust() {
  if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
    log "rustc $(rustc --version 2>/dev/null | awk '{print $2}')"
    log "cargo $(cargo --version 2>/dev/null | awk '{print $2}')"
    return 0
  fi

  # rustup may be installed but not on this shell's PATH yet
  if [ -f "${HOME}/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "${HOME}/.cargo/env"
  fi
  if command -v cargo >/dev/null 2>&1; then
    log "loaded cargo from ~/.cargo/env"
    return 0
  fi

  log "Rust toolchain not found; installing via rustup (https://rustup.rs)"
  need_cmd curl

  if [ "$YES" -ne 1 ] && [ -t 0 ]; then
    printf 'Install rustup into %s? [Y/n] ' "${CARGO_HOME:-$HOME/.cargo}"
    read -r ans || true
    case "${ans:-Y}" in
      n|N|no|NO) die "cargo is required to build pkg-guard" ;;
    esac
  fi

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  # shellcheck disable=SC1091
  . "${HOME}/.cargo/env"
  command -v cargo >/dev/null 2>&1 || die "rustup finished but cargo is still not on PATH"
  log "rustc $(rustc --version | awk '{print $2}')"
}

# Hint for missing C toolchain (common first-run failure on bare VMs / new Macs)
check_linker_hint() {
  if command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; then
    return 0
  fi
  case "$OS" in
    Darwin)
      warn "no C compiler on PATH — install Xcode CLT: xcode-select --install"
      ;;
    Linux)
      warn "no C compiler on PATH — install build tools (e.g. sudo apt install build-essential)"
      ;;
  esac
}

# ─── source tree ─────────────────────────────────────────────────────────────

resolve_source() {
  if [ "$LOCAL_ONLY" -eq 1 ]; then
    # Script lives in <repo>/scripts/install.sh
    local here
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    if [ ! -f "${here}/Cargo.toml" ]; then
      die "--local set but Cargo.toml not found next to scripts/ (${here})"
    fi
    SRC_DIR="$here"
    log "building from local tree: ${SRC_DIR}"
    return 0
  fi

  need_cmd git

  mkdir -p "$(dirname "$SRC_DIR")"
  if [ -d "${SRC_DIR}/.git" ]; then
    log "updating existing checkout: ${SRC_DIR}"
    git -C "$SRC_DIR" remote set-url origin "$REPO" 2>/dev/null || true
    git -C "$SRC_DIR" fetch --tags --force origin
    if git -C "$SRC_DIR" rev-parse --verify "refs/remotes/origin/${REF}" >/dev/null 2>&1; then
      git -C "$SRC_DIR" checkout -B "$REF" "origin/${REF}"
    elif git -C "$SRC_DIR" rev-parse --verify "refs/tags/${REF}" >/dev/null 2>&1; then
      git -C "$SRC_DIR" checkout --detach "refs/tags/${REF}"
    elif git -C "$SRC_DIR" rev-parse --verify "${REF}" >/dev/null 2>&1; then
      git -C "$SRC_DIR" checkout --detach "${REF}"
    else
      die "ref not found after fetch: ${REF}"
    fi
  else
    log "cloning ${REPO} (${REF}) → ${SRC_DIR}"
    rm -rf "$SRC_DIR"
    if git ls-remote --exit-code --heads "$REPO" "$REF" >/dev/null 2>&1; then
      git clone --depth 1 --branch "$REF" "$REPO" "$SRC_DIR"
    elif git ls-remote --exit-code --tags "$REPO" "$REF" >/dev/null 2>&1 \
      || git ls-remote --exit-code --tags "$REPO" "${REF}^{}" >/dev/null 2>&1; then
      git clone --depth 1 --branch "$REF" "$REPO" "$SRC_DIR"
    else
      git clone "$REPO" "$SRC_DIR"
      git -C "$SRC_DIR" checkout "$REF"
    fi
  fi

  [ -f "${SRC_DIR}/Cargo.toml" ] || die "clone missing Cargo.toml"
}

# ─── build & install ─────────────────────────────────────────────────────────

build_release() {
  log "cargo build --release (this may take a few minutes on first build)"
  (
    cd "$SRC_DIR"
    cargo build --release --locked 2>/dev/null || cargo build --release
  )
  local built="${SRC_DIR}/target/release/pkg-guard"
  if [ ! -x "$built" ] && [ -f "${built}.exe" ]; then
    built="${built}.exe"
  fi
  [ -x "$built" ] || die "build finished but binary missing: ${SRC_DIR}/target/release/pkg-guard"
  BUILT_BIN="$built"
}

install_binary() {
  log "installing → ${BIN}"
  mkdir -p "$BINDIR"
  if command -v install >/dev/null 2>&1; then
    install -m 755 "$BUILT_BIN" "$BIN"
  else
    cp "$BUILT_BIN" "$BIN"
    chmod 755 "$BIN"
  fi
  [ -x "$BIN" ] || die "install failed: ${BIN} is not executable"
}

verify() {
  local ver
  ver="$("$BIN" --version 2>/dev/null || true)"
  if [ -z "$ver" ]; then
    warn "binary installed but --version failed"
  else
    log "ok: ${ver}"
  fi

  case ":${PATH}:" in
    *":${BINDIR}:"*) ;;
    *)
      warn "${BINDIR} is not on your PATH"
      printf '\n  Add this to your shell rc (bashrc/zshrc/profile):\n\n'
      printf '    export PATH="%s:$PATH"\n\n' "$BINDIR"
      ;;
  esac
}

# Prefer in-tree setup-user.sh (local or just-cloned). Fall back to remote raw URL
# only when --with-shims runs against an install that somehow lacks the script.
run_user_setup() {
  [ "$WITH_SHIMS" -eq 1 ] || return 0

  local setup="${SRC_DIR}/scripts/setup-user.sh"
  local args=(--bin "$BIN" --tools "$SHIM_TOOLS")
  if [ "$NO_SHELL_RC" -eq 1 ]; then
    args+=(--no-shell-rc)
  fi

  if [ -f "$setup" ]; then
    log "configuring user shims + shell integration"
    bash "$setup" "${args[@]}"
    return 0
  fi

  warn "setup-user.sh missing in source tree — installing shims only"
  case "$SHIM_TOOLS" in
    mcp|MCP|default) SHIM_TOOLS="uvx,uv,npx" ;;
    all|ALL|full)    SHIM_TOOLS="pip,pip3,npm,npx,uvx,uv,cargo" ;;
  esac
  if ! "$BIN" shim install --tools "$SHIM_TOOLS"; then
    warn "shim install failed — run later: pkg-guard shim install --tools uvx,uv,npx"
    return 0
  fi
  printf '\n  Put shims first on PATH (or re-run scripts/setup-user.sh):\n\n'
  printf '    export PATH="$HOME/.local/share/pkg-guard/shims:$PATH"\n\n'
}

maybe_osv() {
  [ "$WITH_OSV" -eq 1 ] || return 0
  log "downloading local OSV dumps (npm is large; can take several minutes)"
  if ! "$BIN" osv update; then
    warn "osv update failed — run later: pkg-guard osv update"
    return 0
  fi
  "$BIN" osv status >/dev/null 2>&1 || true
}

cleanup_src() {
  [ "$KEEP_SRC" -eq 1 ] && return 0
  [ "$LOCAL_ONLY" -eq 1 ] && return 0
  log "removing source checkout (${SRC_DIR})"
  rm -rf "$SRC_DIR"
}

# ─── main ────────────────────────────────────────────────────────────────────

main() {
  log "pkg-guard install-from-source"
  check_linker_hint
  ensure_rust
  resolve_source
  build_release || exit 2
  install_binary || exit 2
  verify
  run_user_setup
  maybe_osv
  cleanup_src

  cat <<EOF

Installed: ${BIN}

Quick checks:
  pkg-guard --help
  pkg-guard check -e python -p requests

EOF

  if [ "$WITH_SHIMS" -eq 1 ]; then
    cat <<'EOF'
Shims (global MCP default: uvx, uv, npx):
  Open a new shell, then:  which -a uvx npx pip
  Status:                  pkg-guard shim status --tools uvx,uv,npx

EOF
  else
    cat <<'EOF'
Optional next steps:
  ./scripts/setup-user.sh          # MCP shims + shim.env + shell rc
  # or:  bash scripts/install.sh --local --with-shims

EOF
  fi

  if [ "$WITH_OSV" -ne 1 ]; then
    cat <<'EOF'
Offline OSV (recommended for CI / large scans):
  pkg-guard osv update
  pkg-guard osv status

EOF
  fi

  cat <<'EOF'
Docs: docs/usage.md  ·  https://github.com/suryan/pkg-guard

EOF
}

main
