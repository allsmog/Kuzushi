#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kuzushi-first-wow.XXXXXX")"
REPORT_PATH="${WORK_DIR}/kuzushi-report.md"

cp "${SCRIPT_DIR}/server.js" "${WORK_DIR}/server.js"

if [[ -n "${KUZUSHI_CMD:-}" ]]; then
  read -r -a KUZUSHI_CMD_ARR <<<"${KUZUSHI_CMD}"
elif [[ -x "${REPO_DIR}/target/debug/kuzushi" ]]; then
  KUZUSHI_CMD_ARR=("${REPO_DIR}/target/debug/kuzushi")
else
  KUZUSHI_CMD_ARR=(cargo run -q -p kuzushi-cli --)
fi

export PATH="${SCRIPT_DIR}/demo-bin:${PATH}"
export KUZUSHI_MODEL="${KUZUSHI_MODEL:-openai:gpt-4.1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-fake-key}"

echo "Target: ${WORK_DIR}"
echo
echo "== doctor =="
"${KUZUSHI_CMD_ARR[@]}" doctor --target "${WORK_DIR}"

echo
echo "== scan =="
"${KUZUSHI_CMD_ARR[@]}" scan "${WORK_DIR}" --mode standard --tasks semgrep --json

echo
echo "== findings =="
"${KUZUSHI_CMD_ARR[@]}" findings --target "${WORK_DIR}" --limit 10

echo
echo "== pr-comment =="
"${KUZUSHI_CMD_ARR[@]}" pr-comment \
  --target "${WORK_DIR}" \
  --repo "demo/first-wow" \
  --git-sha "demo" \
  >"${REPORT_PATH}"

cat "${REPORT_PATH}"

echo
echo "Report: ${REPORT_PATH}"
echo "Findings DB: ${WORK_DIR}/.kuzushi/v2/findings.sqlite3"
