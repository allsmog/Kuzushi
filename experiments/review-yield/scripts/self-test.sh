#!/usr/bin/env bash
# Full offline gate for the review-yield experiment. Spends zero tokens, needs
# zero installs, and touches nothing outside a temporary directory.
#
# Chain: stdlib unit tests -> regenerate the synthetic corpus and compare bytes
# -> train -> evaluate -> export the model artifact -> verify its digest ->
# information-gain audit. Run this after any change to the learner, the
# canonical JSON rule, or the dataset contract.
#
# The optional venv (scripts/setup-venv.sh) adds a scikit-learn comparison and
# the official blake3 binding as a cross-check. Its absence skips those two
# tests and nothing else.

set -euo pipefail

EXPERIMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$EXPERIMENT_DIR"

PYTHON="${PYTHON:-python3}"
if [[ -x .venv/bin/python && "${USE_VENV:-0}" == "1" ]]; then
  PYTHON=".venv/bin/python"
  echo "[self-test] using the extras venv: $PYTHON"
else
  echo "[self-test] using $PYTHON (no extras; sklearn/blake3 tests will skip)"
fi

export PYTHONPATH="src"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "[self-test] unit tests"
"$PYTHON" -m unittest discover -s tests

echo "[self-test] regenerating the synthetic corpus"
"$PYTHON" -m kuzushi_review_yield.dataset --emit-synthetic "$WORK" >/dev/null
cmp fixtures/synthetic-kuzushi-corpus.jsonl "$WORK/synthetic-kuzushi-corpus.jsonl"
cmp fixtures/synthetic-kuzushi-corpus.jsonl.manifest.json \
  "$WORK/synthetic-kuzushi-corpus.jsonl.manifest.json"
echo "[self-test] committed corpus is byte-identical to seed 6601"

echo "[self-test] train, evaluate, export"
"$PYTHON" -m kuzushi_review_yield.train \
  --dataset fixtures/synthetic-kuzushi-corpus.jsonl \
  --manifest fixtures/synthetic-kuzushi-corpus.jsonl.manifest.json \
  --out-dir "$WORK/run" >/dev/null
for artifact in model.json results.json model-card.md tree.txt; do
  test -s "$WORK/run/$artifact" || { echo "missing $artifact"; exit 1; }
done

echo "[self-test] verifying the model artifact digest"
"$PYTHON" -m kuzushi_review_yield.export_model --verify "$WORK/run/model.json"

echo "[self-test] verifying the committed parity fixtures"
for model in fixtures/parity/model-numeric-small.json fixtures/parity/model-mixed-depth3.json; do
  "$PYTHON" -m kuzushi_review_yield.export_model --verify "$model"
done
if "$PYTHON" -m kuzushi_review_yield.export_model \
    --verify fixtures/parity/model-tampered-hash.json 2>/dev/null; then
  echo "tampered fixture verified; the digest check is not failing closed"
  exit 1
fi
echo "[self-test] tampered fixture failed closed, as required"

echo "[self-test] information-gain audit"
"$PYTHON" -m kuzushi_review_yield.ig_audit \
  --dataset fixtures/synthetic-kuzushi-corpus.jsonl \
  --digest synthetic-seed-6601 --out "$WORK/ig-audit.md" >/dev/null
test -s "$WORK/ig-audit.md"

echo "[self-test] OK"
