#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${SCRIPT_DIR}/repo"
REPO_REF="39b46860612990ae18d499a20472172839fe8c77"

if [ -d "${REPO_DIR}" ]; then
  actual_ref="$(git -C "${REPO_DIR}" rev-parse HEAD 2>/dev/null || true)"
  if [[ "${actual_ref}" != "${REPO_REF}" ]]; then
    echo "[juice-shop] Existing checkout is ${actual_ref:-invalid}, expected ${REPO_REF}." >&2
    echo "[juice-shop] Remove ${REPO_DIR} and rerun setup to restore the pinned dataset." >&2
    exit 1
  fi
  echo "[juice-shop] Pinned repository already exists at ${REPO_DIR}."
  exit 0
fi

echo "[juice-shop] Cloning OWASP Juice Shop at ${REPO_REF}..."
git clone --filter=blob:none --no-checkout https://github.com/juice-shop/juice-shop.git "${REPO_DIR}"
git -C "${REPO_DIR}" checkout --detach "${REPO_REF}"
echo "[juice-shop] Clone complete: ${REPO_DIR}"
