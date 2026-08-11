#!/usr/bin/env bash
# Recompute a model artifact's digest the way PR 4's Rust loader will.
#
#   scripts/verify-artifact.sh path/to/model.json

set -euo pipefail

EXPERIMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$EXPERIMENT_DIR"

ARTIFACT="${1:?usage: scripts/verify-artifact.sh <model.json>}"
PYTHON="${PYTHON:-python3}"

PYTHONPATH=src "$PYTHON" -m kuzushi_review_yield.export_model --verify "$ARTIFACT"
