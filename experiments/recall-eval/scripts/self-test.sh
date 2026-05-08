#!/usr/bin/env bash
# Run the recall integration tests against synthetic mini-slices.
# Spends zero tokens; verifies every link in the chain (FindingStore →
# `kuzushi findings --json` → kuzushi-eval scorer → oracle match) is
# wired correctly. Use this after any architectural change that
# touches the schema, the scorer, or the oracle JSONs.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

echo "[self-test] cargo build (debug) — kuzushi + kuzushi-eval"
cargo build -p kuzushi-cli -p kuzushi-eval --quiet

echo "[self-test] running tests/recall_cli.rs"
cargo test -p kuzushi-cli --test recall_cli --quiet -- --nocapture 2>&1 | tail -10

echo "[self-test] OK"
