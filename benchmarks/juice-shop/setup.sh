#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${SCRIPT_DIR}/repo"

if [ -d "${REPO_DIR}" ]; then
  echo "[juice-shop] Repository already exists at ${REPO_DIR}, skipping clone."
  exit 0
fi

echo "[juice-shop] Cloning OWASP Juice Shop v17.1.1..."
git clone --depth 1 --branch v17.1.1 https://github.com/juice-shop/juice-shop.git "${REPO_DIR}"
echo "[juice-shop] Clone complete: ${REPO_DIR}"
