#!/usr/bin/env bash
# pkg-guard user setup (macOS + Linux)
#
# Idempotent helper used by install.sh and `make setup-user`:
#   - install multicall shims (default: MCP launchers only — uvx, uv, npx)
#   - write ~/.config/pkg-guard/shim.env
#   - source shim.env from shell rc files (bash + zsh, login + interactive)
#   - drop a per-project shim template
#
# Usage:
#   ./scripts/setup-user.sh
#   ./scripts/setup-user.sh --tools uvx,uv,npx
#   ./scripts/setup-user.sh --tools all
#   ./scripts/setup-user.sh --no-shims          # shell env only
#   ./scripts/setup-user.sh --no-shell-rc       # shims + shim.env, don't edit rc
#   PKG_GUARD_BIN=~/.local/bin/pkg-guard ./scripts/setup-user.sh
#
# Environment:
#   PKG_GUARD_BIN       path to pkg-guard binary (default: first on PATH or ~/.local/bin)
#   PKG_GUARD_SHIM_DIR  shim directory (passed through to pkg-guard)
#   PKG_GUARD_PREFIX    used to find $PREFIX/bin/pkg-guard when BIN unset

set -euo pipefail

MCP_TOOLS="uvx,uv,npx"
ALL_TOOLS="pip,pip3,npm,npx,uvx,uv,cargo"
TOOLS="$MCP_TOOLS"
INSTALL_SHIMS=1
WRITE_SHELL_RC=1
BIN="${PKG_GUARD_BIN:-}"
PREFIX="${PKG_GUARD_PREFIX:-${HOME}/.local}"

usage() {
  cat <<'EOF'
Usage: setup-user.sh [options]

  Configure global MCP-oriented shims and shell PATH integration.

  --tools LIST     Comma-separated tools, or "mcp" (default) / "all"
  --no-shims       Skip pkg-guard shim install (still write shim.env / rc)
  --no-shell-rc    Do not modify ~/.bashrc ~/.zshrc ~/.profile ~/.zprofile
  --bin PATH       pkg-guard binary (default: PATH / $PKG_GUARD_PREFIX/bin)
  -h, --help       Show this help

Defaults intentionally gate only MCP launchers (uvx, uv, npx). Install
pip/npm/cargo shims per-project — see ~/.config/pkg-guard/project-shims.example.env
EOF
}

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'warn: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --tools)
      TOOLS="${2:-}"; shift 2 ;;
    --tools=*)
      TOOLS="${1#*=}"; shift ;;
    --no-shims)
      INSTALL_SHIMS=0; shift ;;
    --no-shell-rc)
      WRITE_SHELL_RC=0; shift ;;
    --bin)
      BIN="${2:-}"; shift 2 ;;
    --bin=*)
      BIN="${1#*=}"; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      die "unknown option: $1 (try --help)" ;;
  esac
done

case "$TOOLS" in
  mcp|MCP|default) TOOLS="$MCP_TOOLS" ;;
  all|ALL|full)    TOOLS="$ALL_TOOLS" ;;
esac

resolve_bin() {
  if [ -n "$BIN" ] && [ -x "$BIN" ]; then
    return 0
  fi
  if command -v pkg-guard >/dev/null 2>&1; then
    BIN="$(command -v pkg-guard)"
    return 0
  fi
  if [ -x "${PREFIX}/bin/pkg-guard" ]; then
    BIN="${PREFIX}/bin/pkg-guard"
    return 0
  fi
  die "pkg-guard not found; install first or pass --bin /path/to/pkg-guard"
}

config_dir() {
  if [ -n "${XDG_CONFIG_HOME:-}" ]; then
    printf '%s/pkg-guard' "$XDG_CONFIG_HOME"
  else
    printf '%s/.config/pkg-guard' "$HOME"
  fi
}

# Marker used for idempotent rc edits (do not change casually).
RC_MARKER_BEGIN="# >>> pkg-guard shims >>>"
RC_MARKER_END="# <<< pkg-guard shims <<<"
RC_SNIPPET_BODY='[ -f "$HOME/.config/pkg-guard/shim.env" ] && . "$HOME/.config/pkg-guard/shim.env"'

write_shim_env() {
  local dir conf
  dir="$(config_dir)"
  conf="${dir}/shim.env"
  mkdir -p "$dir"
  cat >"$conf" <<'EOF'
# Global pkg-guard shims — MCP launchers only (uvx, uv, npx) by default.
# Leave real package managers where their installers put them.
# For pip/npm/cargo, prefer per-project shims (see project-shims.example.env).
export PATH="${HOME}/.local/share/pkg-guard/shims:${PATH}"
export PKG_GUARD_SHIM_MODE="${PKG_GUARD_SHIM_MODE:-enforce}"
EOF
  # If XDG layout differs, still honor PKG_GUARD_SHIM_DIR when set at runtime.
  if [ -n "${PKG_GUARD_SHIM_DIR:-}" ]; then
    cat >"$conf" <<EOF
# Global pkg-guard shims (PKG_GUARD_SHIM_DIR override)
export PATH="${PKG_GUARD_SHIM_DIR}:\${PATH}"
export PKG_GUARD_SHIM_MODE="\${PKG_GUARD_SHIM_MODE:-enforce}"
EOF
  fi
  log "wrote ${conf}"
}

write_project_template() {
  local dir conf
  dir="$(config_dir)"
  conf="${dir}/project-shims.example.env"
  mkdir -p "$dir"
  cat >"$conf" <<'EOF'
# Per-project package-manager shims (not loaded globally).
#
# From the project root:
#   pkg-guard shim install -d .pkg-guard/shims --tools pip,pip3,npm,cargo
#
# With direnv (.envrc):
#   PATH_add .pkg-guard/shims
#   export PKG_GUARD_SHIM_MODE="${PKG_GUARD_SHIM_MODE:-enforce}"
#   # direnv allow
#
# Or copy these exports into a project-local env file and source it:

export PATH="${PWD}/.pkg-guard/shims:${PATH}"
export PKG_GUARD_SHIM_MODE="${PKG_GUARD_SHIM_MODE:-enforce}"
EOF
  log "wrote ${conf}"
}

# True if this rc already sources pkg-guard shim.env (any marker / prior layout).
rc_already_has_shim() {
  local file="$1"
  [ -f "$file" ] || return 1
  grep -qE 'config/pkg-guard/shim\.env|pkg-guard shims' "$file" 2>/dev/null
}

# Append marker block once per file. Safe on macOS (BSD sed) and GNU.
ensure_rc_snippet() {
  local file="$1"
  local parent
  parent="$(dirname "$file")"
  mkdir -p "$parent"

  if rc_already_has_shim "$file"; then
    log "shell rc already configured: ${file}"
    return 0
  fi

  # Create empty file if missing (common for fresh Linux/macOS accounts).
  if [ ! -f "$file" ]; then
    touch "$file"
  fi

  {
    printf '\n%s\n' "$RC_MARKER_BEGIN"
    printf '%s\n' "$RC_SNIPPET_BODY"
    printf '%s\n' "$RC_MARKER_END"
  } >>"$file"
  log "updated shell rc: ${file}"
}

setup_shell_rc() {
  [ "$WRITE_SHELL_RC" -eq 1 ] || {
    log "skipping shell rc edits (--no-shell-rc)"
    return 0
  }

  # Interactive shells
  ensure_rc_snippet "${HOME}/.bashrc"
  ensure_rc_snippet "${HOME}/.zshrc"
  # Login shells (macOS Terminal, many Linux GUI sessions, SSH login)
  # Source again last so shims stay ahead of ~/.local/bin prepends.
  ensure_rc_snippet "${HOME}/.profile"
  ensure_rc_snippet "${HOME}/.zprofile"
}

install_shims() {
  [ "$INSTALL_SHIMS" -eq 1 ] || {
    log "skipping shim install (--no-shims)"
    return 0
  }

  local args=(shim install --tools "$TOOLS")
  if [ -n "${PKG_GUARD_SHIM_DIR:-}" ]; then
    args+=(--dir "$PKG_GUARD_SHIM_DIR")
  fi

  log "installing shims: ${TOOLS}"
  "$BIN" "${args[@]}"
}

print_summary() {
  local shim_dir="${PKG_GUARD_SHIM_DIR:-${HOME}/.local/share/pkg-guard/shims}"
  cat <<EOF

User setup complete.

  Binary:     ${BIN}
  Shims:      ${shim_dir}  (tools: ${TOOLS})
  Env file:   $(config_dir)/shim.env
  Mode:       PKG_GUARD_SHIM_MODE=enforce (override in shim.env)

Open a new shell (or: source ~/.config/pkg-guard/shim.env), then:

  which -a uvx npx pip cargo
  # uvx/npx → …/pkg-guard/shims/… ; pip/cargo → real tools (global MCP default)

  pkg-guard shim status --tools ${TOOLS}

MCP / IDE hosts often skip shell rc — set PATH in the host env:

  PATH="${shim_dir}:\$PATH"
  PKG_GUARD_SHIM_MODE=enforce

Per-project pip/npm/cargo shims: see $(config_dir)/project-shims.example.env

EOF
}

main() {
  log "pkg-guard user setup (macOS/Linux)"
  resolve_bin
  log "using ${BIN} ($("$BIN" --version 2>/dev/null || echo unknown))"
  install_shims
  write_shim_env
  write_project_template
  setup_shell_rc
  print_summary
}

main
