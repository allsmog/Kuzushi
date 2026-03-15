#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$SCRIPT_DIR/repo"

if [ -d "$REPO_DIR" ]; then
  echo "OWASP BenchmarkJava already cloned at $REPO_DIR"
  echo "To re-clone, remove the directory first: rm -rf $REPO_DIR"
  exit 0
fi

echo "Cloning OWASP BenchmarkJava (shallow)..."
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git "$REPO_DIR"

echo "Generating ground truth..."
cd "$SCRIPT_DIR"
npx tsx convert-ground-truth.ts

echo "Done. Repo at: $REPO_DIR"
echo "Ground truth at: $SCRIPT_DIR/ground-truth.json"
