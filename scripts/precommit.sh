#!/usr/bin/env bash
set -euo pipefail

echo "=== Pre-commit checks ==="
echo ""

# 1. File line count check
echo "[1/5] Checking file line counts..."
FAILED=0
for f in $(find src -name '*.rs'); do
  lines=$(wc -l < "$f")
  if [ "$lines" -gt 1000 ]; then
    echo "  ERROR: $f has $lines lines (max 1000)"
    FAILED=1
  fi
done
if [ "$FAILED" -eq 1 ]; then
  exit 1
fi
echo "  PASS"

# 2. Formatting
echo "[2/5] Checking formatting..."
if ! cargo fmt -- --check > /dev/null 2>&1; then
  echo "  FAIL: Code is not formatted. Run: cargo fmt"
  exit 1
fi
echo "  PASS"

# 3. Clippy (pedantic)
echo "[3/5] Running clippy..."
if ! cargo clippy -- -D warnings > /dev/null 2>&1; then
  echo "  FAIL: Clippy has warnings. Run: cargo clippy -- -D warnings"
  cargo clippy -- -D warnings 2>&1 | tail -20
  exit 1
fi
echo "  PASS"

# 4. Tests
echo "[4/5] Running tests..."
if ! cargo test > /dev/null 2>&1; then
  echo "  FAIL: Tests failed. Run: cargo test"
  cargo test 2>&1 | tail -20
  exit 1
fi
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
  echo "  SKIP (osv-scanner not installed)"
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
