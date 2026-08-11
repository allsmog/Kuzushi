#!/usr/bin/env bash
# Fit, select on validation, evaluate the test fold once, and export the
# artifact plus the model card. Defaults to the committed synthetic corpus.
#
#   scripts/train.sh [dataset.jsonl] [out-dir]

set -euo pipefail

EXPERIMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$EXPERIMENT_DIR"

DATASET="${1:-fixtures/synthetic-kuzushi-corpus.jsonl}"
OUT_DIR="${2:-}"
PYTHON="${PYTHON:-python3}"

ARGS=(--dataset "$DATASET")
if [[ -f "$DATASET.manifest.json" ]]; then
  ARGS+=(--manifest "$DATASET.manifest.json")
fi
if [[ -n "$OUT_DIR" ]]; then
  ARGS+=(--out-dir "$OUT_DIR")
fi
if [[ "${SKLEARN_COMPARISON:-0}" == "1" ]]; then
  ARGS+=(--sklearn-comparison)
fi

PYTHONPATH=src "$PYTHON" -m kuzushi_review_yield.train "${ARGS[@]}"
