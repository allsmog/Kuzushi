#!/usr/bin/env bash
# Print the measured metrics and the gate table for a finished run.
#
#   scripts/evaluate.sh reports/<run-id>

set -euo pipefail

EXPERIMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$EXPERIMENT_DIR"

RUN_DIR="${1:?usage: scripts/evaluate.sh <run-dir>}"
PYTHON="${PYTHON:-python3}"

PYTHONPATH=src "$PYTHON" - "$RUN_DIR" <<'PY'
import json
import sys
from pathlib import Path

run = Path(sys.argv[1])
results = json.loads((run / "results.json").read_text(encoding="utf-8"))

print(f"dataset  {results['datasetDigest']}")
print(f"rows     {results['rows']}")
print(f"selected {results['selected']}")
print("\nmeasured test metrics (single evaluation):")
for name, value in sorted(results["testMetrics"].items()):
    print(f"  {name:<18} {value:.6f}")
print("\nbaselines (P@20% / PR-AUC):")
for name, metrics in sorted(results["baselineMetrics"].items()):
    print(f"  {name:<26} {metrics['precisionAt20']:.6f}  {metrics['prAuc']:.6f}")
print("\nwithin-band queue room:", results["withinBandRoom"])
print("delta P@20% (paired bootstrap):", results["deltaPrecisionAt20"])
print("\ngates:")
for gate in results["gates"]:
    print(f"  {gate['status']:<32} {gate['name']}: {gate['detail']}")
PY
