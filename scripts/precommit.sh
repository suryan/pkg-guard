#!/usr/bin/env bash
set -euo pipefail

echo "=== Pre-commit checks ==="
echo ""

# Minimum line coverage % (override with PKG_GUARD_MIN_COVERAGE).
# main.rs is the multicall/CLI entrypoint — covered by dogfood + manual use;
# library modules under src/ are gated here.
MIN_COVERAGE="${PKG_GUARD_MIN_COVERAGE:-90}"

# 1. File line count check
echo "[1/6] Checking file line counts..."
FAILED=0
while IFS= read -r f; do
  lines=$(wc -l < "$f")
  if [ "$lines" -gt 1000 ]; then
    echo "  ERROR: $f has $lines lines (max 1000)"
    FAILED=1
  fi
done < <(find src -name '*.rs')
if [ "$FAILED" -eq 1 ]; then
  exit 1
fi
echo "  PASS"

# 2. Formatting
echo "[2/6] Checking formatting..."
if ! cargo fmt -- --check > /dev/null 2>&1; then
  echo "  FAIL: Code is not formatted. Run: cargo fmt"
  exit 1
fi
echo "  PASS"

# 3. Clippy (pedantic)
echo "[3/6] Running clippy..."
if ! cargo clippy -- -D warnings > /dev/null 2>&1; then
  echo "  FAIL: Clippy has warnings. Run: cargo clippy -- -D warnings"
  cargo clippy -- -D warnings 2>&1 | tail -20
  exit 1
fi
echo "  PASS"

# 4. Unit tests + line coverage threshold
echo "[4/6] Unit tests + coverage (min ${MIN_COVERAGE}% lines)..."
if ! command -v cargo-llvm-cov >/dev/null 2>&1 && ! cargo llvm-cov --version >/dev/null 2>&1; then
  echo "  FAIL: cargo-llvm-cov is required for coverage."
  echo "  Install: cargo install cargo-llvm-cov --locked"
  echo "  Also ensure LLVM tools: rustup component add llvm-tools-preview"
  exit 1
fi

# Run tests under coverage; fail if line coverage is below threshold.
# Summary is printed; full HTML: cargo llvm-cov --html --output-dir target/llvm-cov
COV_OUT=$(mktemp)
set +e
cargo llvm-cov --summary-only \
  --ignore-filename-regex 'main\.rs' \
  --fail-under-lines "${MIN_COVERAGE}" >"$COV_OUT" 2>&1
COV_RC=$?
set -e

# Always show the TOTAL line for visibility
grep -E '^(TOTAL|Filename)' "$COV_OUT" | tail -8 || true
TOTAL_LINE=$(grep '^TOTAL' "$COV_OUT" | tail -1 || true)
if [ -n "$TOTAL_LINE" ]; then
  # Columns: Regions Missed Cover | Functions ... | Lines Missed Cover | ...
  # Line coverage is the third "Cover" percentage (lines section).
  LINE_PCT=$(echo "$TOTAL_LINE" | awk '{
    for (i=1;i<=NF;i++) if ($i ~ /%$/) { c[++n]=$i }
    if (n>=3) print c[3]; else if (n>=1) print c[n]
  }' | tr -d '%')
  echo "  Line coverage: ${LINE_PCT:-unknown}% (minimum ${MIN_COVERAGE}%)"
fi

if [ "$COV_RC" -ne 0 ]; then
  echo "  FAIL: coverage check failed (exit $COV_RC)."
  echo "  Raise tests or lower PKG_GUARD_MIN_COVERAGE only with intentional review."
  tail -30 "$COV_OUT"
  rm -f "$COV_OUT"
  exit 1
fi
rm -f "$COV_OUT"
echo "  PASS"

# 5. OSV vulnerability scan (external scanner if present)
echo "[5/6] Security audit (osv-scanner)..."
if command -v osv-scanner &> /dev/null; then
  if ! osv-scanner scan --config=osv-scanner.toml . > /dev/null 2>&1; then
    echo "  WARN: Vulnerabilities detected (non-blocking)"
    osv-scanner scan --config=osv-scanner.toml . 2>&1 | tail -10
  else
    echo "  PASS"
  fi
else
  echo "  SKIP (osv-scanner not available)"
fi

# 6. Dogfood: scan Cargo.lock with pkg-guard (blocklist + OSV)
echo "[6/6] pkg-guard Cargo.lock scan..."
PKG_GUARD_BIN=""
if [ -x "./target/debug/pkg-guard" ]; then
  PKG_GUARD_BIN="./target/debug/pkg-guard"
elif [ -x "./target/release/pkg-guard" ]; then
  PKG_GUARD_BIN="./target/release/pkg-guard"
elif command -v pkg-guard &> /dev/null; then
  PKG_GUARD_BIN="pkg-guard"
fi
if [ -n "$PKG_GUARD_BIN" ] && [ -f Cargo.lock ]; then
  # Network OSV may be slow/flaky in CI — fail only on blocklist CRITICAL name hits
  SCAN_OUT=$($PKG_GUARD_BIN scan -f Cargo.lock 2>/dev/null || true)
  if echo "$SCAN_OUT" | grep -q '"findings_count": [1-9]'; then
    echo "  FAIL: blocklisted packages in Cargo.lock"
    echo "$SCAN_OUT" | tail -30
    exit 1
  fi
  if echo "$SCAN_OUT" | grep -q 'OSV malware'; then
    echo "  FAIL: OSV malware advisories in Cargo.lock"
    echo "$SCAN_OUT" | tail -30
    exit 1
  fi
  echo "  PASS"
else
  echo "  SKIP (pkg-guard binary or Cargo.lock missing)"
fi

echo ""
echo "=== Pre-commit checks complete ==="
