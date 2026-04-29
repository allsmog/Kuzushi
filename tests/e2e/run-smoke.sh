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
MOCK_URL_FILE="${TEST_LOG_DIR}/mock-base-url.txt"
MOCK_SERVER_LOG="${TEST_LOG_DIR}/mock-server.log"
# Vendored semgrep rules — committed at tests/e2e/fixtures/semgrep-rules/. We
# point the scanner at this directory instead of `--config auto` so the smoke
# run does not depend on the semgrep registry being reachable from CI (a
# historical flake — see #54).
SEMGREP_RULES_DIR="${REPO_DIR}/tests/e2e/fixtures/semgrep-rules"

# The CLI surfaces a hard error if Anthropic credentials are completely
# absent, even when a non-Anthropic agent runtime is selected (here: pi-ai
# pointing at the mock server). Set a dummy key so credential preflight
# passes — the mock server ignores it. This matches the piAi credential slot below.
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-fake-key}"

# Command used to invoke the Kuzushi CLI. Default `pnpm dev` (tsx) is handy
# locally; CI sets KUZUSHI_CMD="node dist/cli.js" to exercise the built
# artifact. Tokens are whitespace-split (no quoted args).
read -r -a KUZUSHI_CMD_ARR <<<"${KUZUSHI_CMD:-pnpm dev}"

mkdir -p "${TEST_LOG_DIR}"
cat > "${MOCK_MODE_NOTE}" <<'EOF'
Deterministic smoke run using tests/fixtures/mock-anthropic-server.mjs.
This is mock-backed fixture coverage, not a real LLM integration test.
EOF

if ! command -v semgrep >/dev/null 2>&1; then
  echo "semgrep is required for smoke e2e" >&2
  echo "  → install: 'pip install semgrep' or 'brew install semgrep'" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required for smoke e2e (used for mock server readiness probe)" >&2
  exit 1
fi

# Start mock Anthropic API server in the background. Write stdout (which emits
# the base URL on its first line) to MOCK_URL_FILE so we can read it back
# deterministically — avoids the broken `VAR=$(node … &)` pattern.
echo "Running deterministic mock-backed smoke scan; no real LLM calls will be made." >&2
rm -f "${MOCK_URL_FILE}"
: > "${MOCK_SERVER_LOG}"
node "${MOCK_SERVER_SCRIPT}" >"${MOCK_URL_FILE}" 2>"${MOCK_SERVER_LOG}" &
MOCK_PID=$!
trap 'kill "${MOCK_PID}" 2>/dev/null || true' EXIT

# Readiness probe: wait up to 10 s for the mock server to write its URL, then
# confirm it actually answers HTTP requests before proceeding.
MOCK_BASE_URL=""
for _ in $(seq 1 50); do
  if [[ -s "${MOCK_URL_FILE}" ]]; then
    MOCK_BASE_URL="$(head -n1 "${MOCK_URL_FILE}" | tr -d '\r\n')"
    break
  fi
  sleep 0.2
done

if [[ -z "${MOCK_BASE_URL}" ]]; then
  echo "mock Anthropic server did not report a base URL within 10s" >&2
  echo "---- server log ----" >&2
  cat "${MOCK_SERVER_LOG}" >&2 || true
  exit 1
fi

# Confirm reachability — `curl --retry-connrefused` handles the race where the
# server has printed the URL but isn't yet accepting connections on some kernels.
if ! curl --silent --show-error --fail \
     --retry 20 --retry-delay 1 --retry-connrefused \
     --max-time 10 \
     -X POST -H 'Content-Type: application/json' -d '{}' \
     "${MOCK_BASE_URL}/v1/messages" >/dev/null; then
  echo "mock Anthropic server at ${MOCK_BASE_URL} is not responding" >&2
  echo "---- server log ----" >&2
  cat "${MOCK_SERVER_LOG}" >&2 || true
  exit 1
fi
echo "mock server ready at ${MOCK_BASE_URL}" >&2

export GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-Kuzushi Smoke}"
export GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-smoke@example.com}"
export GIT_COMMITTER_NAME="${GIT_COMMITTER_NAME:-$GIT_AUTHOR_NAME}"
export GIT_COMMITTER_EMAIL="${GIT_COMMITTER_EMAIL:-$GIT_AUTHOR_EMAIL}"

bash "${SCRIPT_DIR}/setup-test-app.sh" "${TEST_APP_DIR}" >"${TEST_LOG_DIR}/setup.log" 2>&1

cat > "${TEST_APP_DIR}/.kuzushi/config.json" <<JSON
{
  "model": "anthropic:claude-sonnet-4-6",
  "agentRuntimeBackend": "pi-ai",
  "agentRuntimeConfig": { "piAi": { "baseUrl": "${MOCK_BASE_URL}", "apiKey": "fake-key" } },
  "scanners": ["semgrep"],
  "enabledTasks": ["context-gatherer"],
  "verify": false,
  "triageConcurrency": 1,
  "triageBatchSize": 1,
  "scanMode": "sequential",
  "auditLog": false,
  "enableContextGathering": false,
  "enableContextEnrichment": false,
  "enableDynamicTaskSelection": false,
  "llmRescoreEnabled": false,
  "fpFilterEnabled": false,
  "taskConfig": {
    "semgrep": {
      "configFlag": ["${SEMGREP_RULES_DIR}"]
    }
  }
}
JSON

"${KUZUSHI_CMD_ARR[@]}" config validate --repo "${TEST_APP_DIR}" --trust-repo-config >"${TEST_LOG_DIR}/config-validate.log" 2>&1
"${KUZUSHI_CMD_ARR[@]}" scan "${TEST_APP_DIR}" --trust-repo-config --fresh --max 3 --sarif "${SARIF_PATH}" >"${TEST_LOG_DIR}/scan.log" 2>&1

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
