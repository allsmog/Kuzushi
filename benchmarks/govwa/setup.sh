#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${SCRIPT_DIR}/repo"

if [ -d "${REPO_DIR}" ]; then
  echo "[govwa] Repository already exists at ${REPO_DIR}, skipping clone."
  exit 0
fi

echo "[govwa] Cloning Go Vulnerable Web Application..."
git clone --depth 1 https://github.com/0c34/govwa.git "${REPO_DIR}"
echo "[govwa] Clone complete: ${REPO_DIR}"
