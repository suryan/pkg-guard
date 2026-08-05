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

# 5. OSV vulnerability scan
echo "[5/5] Security audit..."
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

echo ""
echo "=== Pre-commit checks complete ==="
