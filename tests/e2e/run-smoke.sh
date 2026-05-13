#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_APP_DIR="${TEST_APP_DIR:-/tmp/kuzushi-smoke-app}"
TEST_LOG_DIR="${TEST_LOG_DIR:-/tmp/kuzushi-smoke-logs}"
FAKE_BIN_DIR="${TEST_LOG_DIR}/bin"
DB_PATH="${TEST_APP_DIR}/.kuzushi/v2/findings.sqlite3"
HOST_TRIPLE="$(node -p '`${process.platform}-${process.arch}`')"
DOWNLOADED_NATIVE_BIN="${REPO_DIR}/native/${HOST_TRIPLE}/kuzushi"

# Command used to invoke the Kuzushi CLI. CI can set
# KUZUSHI_CMD="node bin/kuzushi-rs.mjs" after downloading native/.
if [[ -n "${KUZUSHI_CMD:-}" ]]; then
  read -r -a KUZUSHI_CMD_ARR <<<"${KUZUSHI_CMD}"
elif [[ -x "${REPO_DIR}/target/debug/kuzushi" ]]; then
  KUZUSHI_CMD_ARR=("${REPO_DIR}/target/debug/kuzushi")
else
  KUZUSHI_CMD_ARR=(cargo run -q -p kuzushi-cli --)
fi

mkdir -p "${TEST_LOG_DIR}" "${FAKE_BIN_DIR}"

bash "${SCRIPT_DIR}/setup-test-app.sh" "${TEST_APP_DIR}" >"${TEST_LOG_DIR}/setup.log" 2>&1

cat >"${FAKE_BIN_DIR}/semgrep" <<'SH'
#!/usr/bin/env sh
cat <<'JSON'
{
  "results": [
    {
      "check_id": "javascript.express.security.audit.xss",
      "path": "server.js",
      "start": { "line": 9 },
      "end": { "line": 11 },
      "extra": {
        "severity": "ERROR",
        "message": "Detected unescaped user input in HTML response"
      }
    },
    {
      "check_id": "javascript.lang.security.audit.command-injection",
      "path": "server.js",
      "start": { "line": 16 },
      "end": { "line": 19 },
      "extra": {
        "severity": "WARNING",
        "message": "Detected user input flowing into child_process.exec"
      }
    }
  ]
}
JSON
SH
chmod +x "${FAKE_BIN_DIR}/semgrep"

export PATH="${FAKE_BIN_DIR}:${PATH}"
export KUZUSHI_MODEL="${KUZUSHI_MODEL:-openai:gpt-4.1}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-fake-key}"

if [[ -z "${KUZUSHI_NATIVE_BIN:-}" && -x "${DOWNLOADED_NATIVE_BIN}" ]]; then
  export KUZUSHI_NATIVE_BIN="${DOWNLOADED_NATIVE_BIN}"
fi

if [[ -z "${KUZUSHI_NATIVE_BIN:-}" && ! -x "${REPO_DIR}/target/debug/kuzushi" ]]; then
  cargo build -q -p kuzushi-cli
fi
KUZUSHI_NATIVE_BIN="${KUZUSHI_NATIVE_BIN:-${REPO_DIR}/target/debug/kuzushi}" \
  node "${REPO_DIR}/bin/kuzushi-rs.mjs" --help >"${TEST_LOG_DIR}/wrapper-help.log" 2>&1
grep -q "Kuzushi security-native code agent" "${TEST_LOG_DIR}/wrapper-help.log"
grep -q "modules" "${TEST_LOG_DIR}/wrapper-help.log"

"${KUZUSHI_CMD_ARR[@]}" --target "${TEST_APP_DIR}" config show >"${TEST_LOG_DIR}/config-show.log" 2>&1
"${KUZUSHI_CMD_ARR[@]}" scan "${TEST_APP_DIR}" --json >"${TEST_LOG_DIR}/scan.json" 2>"${TEST_LOG_DIR}/scan.err"
"${KUZUSHI_CMD_ARR[@]}" findings --target "${TEST_APP_DIR}" --limit 10 --json >"${TEST_LOG_DIR}/findings.json" 2>&1

if [[ ! -f "${DB_PATH}" ]]; then
  echo "expected findings database at ${DB_PATH}" >&2
  exit 1
fi

node --input-type=module - "${TEST_LOG_DIR}/scan.json" "${TEST_LOG_DIR}/findings.json" <<'NODE'
import { readFileSync } from "node:fs";

const scan = JSON.parse(readFileSync(process.argv[2], "utf8"));
const findingsReport = JSON.parse(readFileSync(process.argv[3], "utf8"));
const findings = Array.isArray(findingsReport) ? findingsReport : findingsReport.findings;

if (!scan.runId || scan.findingsCount !== 2) {
  console.error(`expected scan JSON with two findings, got ${JSON.stringify(scan)}`);
  process.exit(1);
}

if (!Array.isArray(findings) || findings.length !== 2) {
  console.error(`expected two persisted findings, got ${JSON.stringify(findingsReport)}`);
  process.exit(1);
}

const titles = findings.map((finding) => finding.title).join("\n");
if (!titles.includes("Detected unescaped user input")) {
  console.error(`expected XSS finding in persisted output, got ${titles}`);
  process.exit(1);
}
NODE

echo "native smoke passed: ${DB_PATH}"
