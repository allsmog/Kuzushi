#!/usr/bin/env bash
set -euo pipefail

OUTPUT="${1:-kuzushi-source.tar.gz}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "export-clean-source must run inside a git checkout" >&2
  exit 2
fi

COMMIT_SHA="${KUZUSHI_SOURCE_COMMIT:-$(git rev-parse HEAD)}"
node scripts/export-clean-source.mjs "${COMMIT_SHA}" "${OUTPUT}"
