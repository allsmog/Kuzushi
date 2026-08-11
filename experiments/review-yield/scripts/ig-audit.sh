#!/usr/bin/env bash
# The standalone information-gain audit. This report ships regardless of whether
# any model is ever promoted: it audits Kuzushi's review assumptions, not a model.
#
#   scripts/ig-audit.sh [dataset.jsonl] [out.md]

set -euo pipefail

EXPERIMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$EXPERIMENT_DIR"

DATASET="${1:-fixtures/synthetic-kuzushi-corpus.jsonl}"
OUT="${2:-reports/ig-audit.md}"
PYTHON="${PYTHON:-python3}"

DIGEST="unnamed-dataset"
if [[ -f "$DATASET.manifest.json" ]]; then
  DIGEST="$(PYTHONPATH=src "$PYTHON" -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["datasetDigest"])' \
    "$DATASET.manifest.json")"
fi

PYTHONPATH=src "$PYTHON" -m kuzushi_review_yield.ig_audit \
  --dataset "$DATASET" --digest "$DIGEST" --out "$OUT"
