#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${SCRIPT_DIR}/repo"
REPO_REF="4058f79f31eeb4a36d8f1e64bba1f0c899646e6f"

if [ -d "${REPO_DIR}" ]; then
  actual_ref="$(git -C "${REPO_DIR}" rev-parse HEAD 2>/dev/null || true)"
  if [[ "${actual_ref}" != "${REPO_REF}" ]]; then
    echo "[govwa] Existing checkout is ${actual_ref:-invalid}, expected ${REPO_REF}." >&2
    echo "[govwa] Remove ${REPO_DIR} and rerun setup to restore the pinned dataset." >&2
    exit 1
  fi
  echo "[govwa] Pinned repository already exists at ${REPO_DIR}."
  exit 0
fi

echo "[govwa] Cloning Go Vulnerable Web Application..."
git clone --filter=blob:none --no-checkout https://github.com/0c34/govwa.git "${REPO_DIR}"
git -C "${REPO_DIR}" checkout --detach "${REPO_REF}"
echo "[govwa] Clone complete: ${REPO_DIR}"
