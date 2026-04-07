#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_APP_DIR="${TEST_APP_DIR:-/tmp/kuzushi-smoke-app}"
TEST_LOG_DIR="${TEST_LOG_DIR:-/tmp/kuzushi-smoke-logs}"
SARIF_PATH="${TEST_LOG_DIR}/results.sarif"
DB_PATH="${TEST_APP_DIR}/.kuzushi/findings.sqlite3"
MOCK_SERVER_SCRIPT="${REPO_DIR}/tests/fixtures/mock-anthropic-server.mjs"
MOCK_MODE_NOTE="${TEST_LOG_DIR}/mock-mode.txt"

mkdir -p "${TEST_LOG_DIR}"
cat > "${MOCK_MODE_NOTE}" <<'EOF'
Deterministic smoke run using tests/fixtures/mock-anthropic-server.mjs.
This is mock-backed fixture coverage, not a real LLM integration test.
EOF

# Start mock Anthropic API server and capture its base URL.
echo "Running deterministic mock-backed smoke scan; no real LLM calls will be made." >&2
MOCK_BASE_URL=$(node "${MOCK_SERVER_SCRIPT}" &)
MOCK_PID=$!
trap 'kill $MOCK_PID 2>/dev/null || true' EXIT

if ! command -v semgrep >/dev/null 2>&1; then
  echo "semgrep is required for smoke e2e" >&2
  exit 1
fi

export GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-Kuzushi Smoke}"
export GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-smoke@example.com}"
export GIT_COMMITTER_NAME="${GIT_COMMITTER_NAME:-$GIT_AUTHOR_NAME}"
export GIT_COMMITTER_EMAIL="${GIT_COMMITTER_EMAIL:-$GIT_AUTHOR_EMAIL}"

bash "${SCRIPT_DIR}/setup-test-app.sh" "${TEST_APP_DIR}" >"${TEST_LOG_DIR}/setup.log" 2>&1

cat > "${TEST_APP_DIR}/.kuzushi/config.json" <<JSON
{
  "model": "anthropic:claude-sonnet-4-6",
  "agentRuntimeConfig": { "baseUrl": "${MOCK_BASE_URL}", "apiKey": "fake-key" },
  "scanners": ["semgrep"],
  "enabledTasks": ["context-gatherer"],
  "verify": false,
  "triageConcurrency": 1,
  "triageBatchSize": 1,
  "scanMode": "sequential",
  "auditLog": false,
  "enableContextGathering": false,
  "enableContextEnrichment": false,
  "llmRescoreEnabled": false,
  "fpFilterEnabled": false
}
JSON

pnpm dev config validate --repo "${TEST_APP_DIR}" --trust-repo-config >"${TEST_LOG_DIR}/config-validate.log" 2>&1
pnpm dev scan "${TEST_APP_DIR}" --trust-repo-config --fresh --max 3 --sarif "${SARIF_PATH}" >"${TEST_LOG_DIR}/scan.log" 2>&1

if [[ ! -f "${SARIF_PATH}" ]]; then
  echo "expected SARIF output at ${SARIF_PATH}" >&2
  exit 1
fi

if [[ ! -f "${DB_PATH}" ]]; then
  echo "expected findings database at ${DB_PATH}" >&2
  exit 1
fi

node --input-type=module - "${SARIF_PATH}" <<'NODE'
import { readFileSync } from "node:fs";

const sarifPath = process.argv[2];
const sarif = JSON.parse(readFileSync(sarifPath, "utf-8"));
const results = sarif.runs?.[0]?.results ?? [];

if (!Array.isArray(results) || results.length === 0) {
  console.error(`expected at least one SARIF result in ${sarifPath}`);
  process.exit(1);
}
NODE

node --input-type=module - "${DB_PATH}" <<'NODE'
import Database from "better-sqlite3";

const dbPath = process.argv[2];
const db = new Database(dbPath, { readonly: true });

try {
  const findingCount = db.prepare("SELECT COUNT(*) AS count FROM findings").get();
  if (!findingCount || typeof findingCount.count !== "number" || findingCount.count === 0) {
    console.error(`expected persisted findings in ${dbPath}`);
    process.exit(1);
  }
} finally {
  db.close();
}
NODE
