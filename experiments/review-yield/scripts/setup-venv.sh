#!/usr/bin/env bash
# Optional extras only: a scikit-learn comparison tree and the official blake3
# binding used as a cross-check on the stdlib implementation. Nothing in the
# core learner, the exporter, or the test suite requires this venv.

set -euo pipefail

EXPERIMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$EXPERIMENT_DIR"

python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet scikit-learn blake3
echo "extras installed. Run the suite against them with:"
echo "  USE_VENV=1 scripts/self-test.sh"
