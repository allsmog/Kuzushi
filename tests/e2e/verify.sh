#!/usr/bin/env bash
# verify.sh — Helper functions for E2E test verification.
# Sourced by run-e2e.sh.

set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo -e "  ${GREEN}✓${NC} $1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo -e "  ${RED}✗${NC} $1"
  if [[ -n "${2:-}" ]]; then
    echo -e "    ${RED}→ $2${NC}"
  fi
}

skip() {
  SKIP_COUNT=$((SKIP_COUNT + 1))
  echo -e "  ${YELLOW}⊘${NC} $1 (skipped: ${2:-prerequisite missing})"
}

info() {
  echo -e "  ${CYAN}ℹ${NC} $1"
}

header() {
  echo ""
  echo -e "${CYAN}━━━ $1 ━━━${NC}"
}

summary() {
  echo ""
  echo -e "${CYAN}━━━ Summary ━━━${NC}"
  echo -e "  ${GREEN}Passed: ${PASS_COUNT}${NC}"
  echo -e "  ${RED}Failed: ${FAIL_COUNT}${NC}"
  echo -e "  ${YELLOW}Skipped: ${SKIP_COUNT}${NC}"
  local TOTAL=$((PASS_COUNT + FAIL_COUNT))
  if [[ $FAIL_COUNT -eq 0 && $TOTAL -gt 0 ]]; then
    echo -e "  ${GREEN}All checks passed.${NC}"
  elif [[ $TOTAL -eq 0 ]]; then
    echo -e "  ${YELLOW}No checks ran.${NC}"
  else
    echo -e "  ${RED}${FAIL_COUNT}/${TOTAL} checks failed.${NC}"
  fi
}

# ─── DB helpers ───────────────────────────────────────────────────────

# Run a SQLite query on the test app's findings DB.
# Usage: db_query "SELECT ..." [db_path]
db_query() {
  local query="$1"
  local db="${2:-${TEST_APP_DIR}/.kuzushi/findings.sqlite3}"
  if [[ ! -f "$db" ]]; then
    echo "__DB_MISSING__"
    return
  fi
  sqlite3 -header -separator '|' "$db" "$query" 2>/dev/null || echo "__QUERY_ERROR__"
}

# Count rows returned by a query.
db_count() {
  local query="$1"
  local db="${2:-${TEST_APP_DIR}/.kuzushi/findings.sqlite3}"
  local result
  result=$(db_query "$query" "$db")
  if [[ "$result" == "__DB_MISSING__" || "$result" == "__QUERY_ERROR__" ]]; then
    echo "0"
    return
  fi
  echo "$result" | tail -1
}

# Check that a column exists in the findings table (exact match).
db_column_exists() {
  local column="$1"
  local db="${2:-${TEST_APP_DIR}/.kuzushi/findings.sqlite3}"
  local result
  result=$(sqlite3 "$db" "PRAGMA table_info(findings)" 2>/dev/null || echo "")
  # PRAGMA table_info returns: cid|name|type|notnull|dflt_value|pk — match on field 2 exactly.
  echo "$result" | awk -F'|' -v col="$column" '$2 == col {found=1} END {exit !found}'
}

# ─── Audit log helpers ────────────────────────────────────────────────

# Find the most recent run directory.
# Usage: latest_run_dir [app_dir]
latest_run_dir() {
  local app_dir="${1:-${TEST_APP_DIR}}"
  local runs_dir="${app_dir}/.kuzushi/runs"
  if [[ ! -d "$runs_dir" ]]; then
    echo ""
    return
  fi
  # Run dirs are UUIDs; sort by modification time.
  ls -1t "$runs_dir" 2>/dev/null | head -1 | while read -r d; do
    echo "${runs_dir}/${d}"
  done
}

# Read audit JSONL and grep for a pattern.
# Usage: audit_grep "pattern" "triage|verify" [run_dir]
audit_grep() {
  local pattern="$1"
  local stream="${2:-triage}"
  local run_dir="${3:-$(latest_run_dir)}"
  if [[ -z "$run_dir" || ! -d "$run_dir" ]]; then
    echo ""
    return
  fi
  local logfile="${run_dir}/${stream}.jsonl"
  if [[ ! -f "$logfile" ]]; then
    echo ""
    return
  fi
  grep -i "$pattern" "$logfile" 2>/dev/null || true
}

# Count lines in an audit JSONL file.
audit_line_count() {
  local stream="${1:-triage}"
  local run_dir="${2:-$(latest_run_dir)}"
  if [[ -z "$run_dir" || ! -d "$run_dir" ]]; then
    echo "0"
    return
  fi
  local logfile="${run_dir}/${stream}.jsonl"
  if [[ ! -f "$logfile" ]]; then
    echo "0"
    return
  fi
  wc -l < "$logfile" | tr -d ' '
}

# ─── Findings helpers ─────────────────────────────────────────────────

# Count findings in the DB.
findings_count() {
  db_count "SELECT COUNT(*) FROM findings" "${1:-}"
}

# Get distinct verdicts.
findings_verdicts() {
  db_query "SELECT DISTINCT verdict FROM findings" "${1:-}"
}

# Check if composite_confidence column has non-null values.
has_composite_confidence() {
  local count
  count=$(db_count "SELECT COUNT(*) FROM findings WHERE composite_confidence IS NOT NULL")
  [[ "$count" -gt 0 ]]
}

# Check if composite_confidence differs from confidence for at least one finding.
composite_differs_from_confidence() {
  local count
  count=$(db_count "SELECT COUNT(*) FROM findings WHERE composite_confidence IS NOT NULL AND ABS(composite_confidence - confidence) > 0.001")
  [[ "$count" -gt 0 ]]
}

# ─── Scanner cache helpers ────────────────────────────────────────────

scanner_cache_count() {
  local db="${1:-${TEST_APP_DIR}/.kuzushi/findings.sqlite3}"
  # Check if scanner_cache table exists first.
  local tables
  tables=$(sqlite3 "$db" ".tables" 2>/dev/null || echo "")
  if ! echo "$tables" | grep -q "scanner_cache"; then
    echo "0"
    return
  fi
  db_count "SELECT COUNT(*) FROM scanner_cache" "$db"
}

# ─── Process helpers ──────────────────────────────────────────────────

# Check if ollama is running and has the model.
check_ollama() {
  local model="${1:-qwen2.5-coder:7b}"
  if ! command -v ollama &>/dev/null; then
    echo "missing"
    return
  fi
  if ! curl -s http://localhost:11434/api/tags &>/dev/null; then
    echo "not-running"
    return
  fi
  if ! ollama list 2>/dev/null | grep -q "$model"; then
    echo "no-model"
    return
  fi
  echo "ok"
}

# Check if semgrep is installed.
check_semgrep() {
  if command -v semgrep &>/dev/null; then
    echo "ok"
  else
    echo "missing"
  fi
}

# Check if codeql is installed.
check_codeql() {
  if command -v codeql &>/dev/null; then
    echo "ok"
  else
    echo "missing"
  fi
}

# ─── Run kuzushi with timeout ────────────────────────────────────────

# Runs kuzushi with a timeout. Returns exit code.
# Usage: run_kuzushi [extra_args...]
run_kuzushi() {
  local timeout_secs="${KUZUSHI_TIMEOUT:-600}"
  local kuzushi_dir="${KUZUSHI_DIR}"

  info "Running: pnpm dev scan $*"

  # Use timeout if available (coreutils on macOS via brew, built-in on Linux).
  local timeout_cmd=""
  if command -v timeout &>/dev/null; then
    timeout_cmd="timeout ${timeout_secs}"
  elif command -v gtimeout &>/dev/null; then
    timeout_cmd="gtimeout ${timeout_secs}"
  fi

  local exit_code=0
  (
    cd "$kuzushi_dir"
    # Ollama's OpenAI-compatible API doesn't need a real key, but the CLI
    # validator requires OPENAI_API_KEY to be set for openai: model specs.
    export OPENAI_API_KEY="${OPENAI_API_KEY:-ollama}"
    if [[ -n "$timeout_cmd" ]]; then
      $timeout_cmd pnpm dev scan --trust-repo-config "$@" 2>&1
    else
      pnpm dev scan --trust-repo-config "$@" 2>&1
    fi
  ) || exit_code=$?

  return $exit_code
}
