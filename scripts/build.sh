#!/usr/bin/env bash
set -euo pipefail

echo "=== pkg-guard build ==="
echo ""

echo "Checking file line counts..."
FAILED=0
for f in $(find src -name '*.rs'); do
  lines=$(wc -l < "$f")
  if [ "$lines" -gt 1000 ]; then
    echo "ERROR: $f has $lines lines (max 1000)"
    FAILED=1
  fi
done
if [ -d tests ]; then
  for f in $(find tests -name '*.rs'); do
    lines=$(wc -l < "$f")
    if [ "$lines" -gt 1000 ]; then
      echo "ERROR: $f has $lines lines (max 1000)"
      FAILED=1
    fi
  done
fi
if [ "$FAILED" -eq 1 ]; then
  exit 1
fi
echo "File line counts OK"

echo ""
echo "Checking formatting..."
cargo fmt -- --check

echo ""
echo "Running clippy (pedantic)..."
cargo clippy -- -D warnings

echo ""
echo "Scanning for vulnerabilities..."
if command -v osv-scanner &> /dev/null; then
  osv-scanner scan --config=osv-scanner.toml .
else
  echo "WARN: osv-scanner not installed, skipping vulnerability scan"
fi

echo ""
echo "Running tests..."
cargo test

echo ""
echo "Building release binary..."
cargo build --release

echo ""
echo "Build complete: target/release/pkg-guard"
echo ""
echo "=== All checks passed ==="
