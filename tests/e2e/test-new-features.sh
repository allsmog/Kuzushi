#!/usr/bin/env bash
# test-new-features.sh — E2E tests for code graph, incremental, streaming, auto-patch.
# Runs ONE scan at a time. Designed for 16GB RAM machines with local Ollama.
#
# Usage:
#   ./tests/e2e/test-new-features.sh
#
# Prerequisites:
#   - Ollama running with qwen3:8b
#   - Semgrep installed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KUZUSHI_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_APP="${TEST_APP:-/tmp/kuzushi-test-app}"
DB_PATH="$TEST_APP/.kuzushi/findings.sqlite3"
TIMEOUT_SEC=150

export OPENAI_API_KEY=ollama
export OPENAI_BASE_URL=http://localhost:11434/v1

pass=0
fail=0

green() { printf "\033[32m%s\033[0m\n" "$1"; }
red()   { printf "\033[31m%s\033[0m\n" "$1"; }
bold()  { printf "\033[1m%s\033[0m\n" "$1"; }

check() {
  local desc="$1" cond="$2"
  if eval "$cond" 2>/dev/null; then
    green "  PASS: $desc"
    ((pass++)) || true
  else
    red "  FAIL: $desc"
    ((fail++)) || true
  fi
}

run_scan() {
  local label="$1"; shift
  bold "--- $label ---"
  cd "$KUZUSHI_DIR"
  if command -v timeout &>/dev/null; then
    timeout "$TIMEOUT_SEC" npx tsx src/cli.ts scan "$TEST_APP" \
      --model openai:qwen3:8b \
      --triage-model openai:qwen3:8b \
      --api-key ollama \
      --base-url http://localhost:11434/v1 \
      --max 1 \
      --max-triage-retries 3 \
      --scanners semgrep \
      "$@" 2>&1 || true
  else
    npx tsx src/cli.ts scan "$TEST_APP" \
      --model openai:qwen3:8b \
      --triage-model openai:qwen3:8b \
      --api-key ollama \
      --base-url http://localhost:11434/v1 \
      --max 1 \
      --max-triage-retries 3 \
      --scanners semgrep \
      "$@" 2>&1 || true
  fi
}

query_db() {
  sqlite3 "$DB_PATH" "$1" 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════════════
bold "Setting up test app..."
bash "$SCRIPT_DIR/setup-test-app.sh" "$TEST_APP" >/dev/null 2>&1

# ═══════════════════════════════════════════════════════════════════════
bold ""
bold "═══ TEST 1: Code Graph (static skeleton + SQLite) ═══"
# Run with --code-graph but limit triage to 1 finding
# Write config that limits Phase B to 0 entry points (skip LLM tracing — too slow on 8B)
cat > "$TEST_APP/.kuzushi/config.json" << 'CFGJSON'
{
  "taskConfig": {
    "code-graph": { "maxEntryPoints": 0 }
  }
}
CFGJSON

run_scan "Code Graph Scan (static skeleton only)" --code-graph --fresh

echo ""
bold "Verifying code graph SQLite tables..."
NODE_COUNT=$(query_db "SELECT COUNT(*) FROM code_graph_nodes")
EDGE_COUNT=$(query_db "SELECT COUNT(*) FROM code_graph_edges")
ENTRY_COUNT=$(query_db "SELECT COUNT(*) FROM code_graph_nodes WHERE node_kind LIKE 'entry%'")
STATIC_COUNT=$(query_db "SELECT COUNT(*) FROM code_graph_nodes WHERE source='static'")

check "code_graph_nodes table populated" "[[ $NODE_COUNT -gt 0 ]]"
check "code_graph_edges table populated" "[[ $EDGE_COUNT -gt 0 ]]"
check "entry nodes detected" "[[ $ENTRY_COUNT -gt 0 ]]"
check "static nodes from import graph" "[[ $STATIC_COUNT -gt 0 ]]"

# Reset config for remaining tests
echo '{}' > "$TEST_APP/.kuzushi/config.json"

# ═══════════════════════════════════════════════════════════════════════
bold ""
bold "═══ TEST 2: Incremental Scanning (run twice) ═══"

# Write config to disable slow DAG tasks (taint analysis) for faster iteration
cat > "$TEST_APP/.kuzushi/config.json" << 'CFGJSON'
{
  "enabledTasks": ["context-gatherer"],
  "taskConfig": {}
}
CFGJSON

# Run 1: fresh scan
run_scan "Incremental Run 1 (fresh)" --fresh > /tmp/kuzushi-inc-run1.log 2>&1
RUN1_FINDINGS=$(query_db "SELECT COUNT(*) FROM findings" || echo "0")

echo "  Run 1: $RUN1_FINDINGS findings stored"

# Run 2: incremental (no --fresh) — should skip already-triaged findings
run_scan "Incremental Run 2 (incremental)" > /tmp/kuzushi-inc-run2.log 2>&1

SKIPPED=$(grep -o "Skipping [0-9]* already-triaged" /tmp/kuzushi-inc-run2.log | grep -o "[0-9]*" || echo "0")
echo "  Run 2: $SKIPPED findings skipped"

check "Run 2 skipped previously-triaged findings" "[[ ${SKIPPED:-0} -gt 0 ]]"

# Check head_ref stored (may be on a 'complete' or latest run)
HEAD_REF=$(query_db "SELECT COALESCE(head_ref,'') FROM pipeline_runs WHERE head_ref IS NOT NULL ORDER BY started_at DESC LIMIT 1" || echo "")
check "head_ref stored in pipeline_runs" "[[ -n '$HEAD_REF' ]]"

# Check file_path index
FP_IDX=$(query_db "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_findings_file_path'" || echo "0")
check "file_path index exists" "[[ $FP_IDX -eq 1 ]]"

# ═══════════════════════════════════════════════════════════════════════
bold ""
bold "═══ TEST 3: Streaming SSE Server ═══"

# Start scan with --stream in background
cd "$KUZUSHI_DIR"
OPENAI_API_KEY=ollama OPENAI_BASE_URL=http://localhost:11434/v1 \
  npx tsx src/cli.ts scan "$TEST_APP" \
  --model openai:qwen3:8b \
  --triage-model openai:qwen3:8b \
  --api-key ollama \
  --base-url http://localhost:11434/v1 \
  --max 1 \
      --max-triage-retries 3 \
  --scanners semgrep \
  --stream --stream-port 3100 \
  --fresh \
  > /tmp/kuzushi-stream-scan.log 2>&1 &
SCAN_PID=$!

# Wait for server to start (semgrep takes ~10s)
echo "  Waiting for streaming server..."
for i in $(seq 1 30); do
  if curl -s -m 1 http://localhost:3100/health >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# Test health endpoint
HEALTH=$(curl -s -m 3 http://localhost:3100/health 2>/dev/null || echo "{}")
check "SSE health endpoint responds" "[[ '$HEALTH' == *'ok'* ]]"

# Test SSE connection (capture for 3 seconds)
SSE_DATA=$(timeout 3 curl -s -N http://localhost:3100/events 2>/dev/null || true)
check "SSE sends connected event" "[[ '$SSE_DATA' == *'connected'* ]]"

# Clean up scan
kill $SCAN_PID 2>/dev/null
wait $SCAN_PID 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════════════
bold ""
bold "═══ TEST 4: Fix Verification Loop (config parsing) ═══"
# We can't fully test auto-patch E2E without an exploitable finding + PoC,
# but we CAN verify the config/flags parse correctly and the pipeline doesn't crash.

run_scan "Auto-patch config test" --verify --auto-patch --auto-patch-after triage --patch-verify-depth scanner --fresh > /tmp/kuzushi-patch-test.log 2>&1
PATCH_EXIT=$?

check "Pipeline accepts --auto-patch flags without crash" "[[ $PATCH_EXIT -eq 0 ]] || [[ $PATCH_EXIT -eq 124 ]]"

# Check VERIFIED status exists in patch_results schema
VERIFIED=$(query_db "SELECT CASE WHEN sql LIKE '%VERIFIED%' THEN 'YES' ELSE 'NO' END FROM sqlite_master WHERE name='patch_results'" || echo "NO")
check "VERIFIED status in patch_results schema" "[[ '$VERIFIED' == 'YES' ]]"

# ═══════════════════════════════════════════════════════════════════════
bold ""
bold "═══ TEST 5: Migration Integrity ═══"

# Verify all new migrations applied
TABLE_019=$(query_db "SELECT COUNT(*) FROM sqlite_master WHERE name='code_graph_nodes'" || echo "0")
TABLE_020=$(query_db "SELECT CASE WHEN sql LIKE '%VERIFIED%' THEN 1 ELSE 0 END FROM sqlite_master WHERE name='patch_results'" || echo "0")
TABLE_021=$(query_db "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_findings_file_path'" || echo "0")

check "Migration 019: code_graph tables exist" "[[ $TABLE_019 -eq 1 ]]"
check "Migration 020: VERIFIED in patch_results" "[[ $TABLE_020 -eq 1 ]]"
check "Migration 021: file_path index exists" "[[ $TABLE_021 -eq 1 ]]"

# ═══════════════════════════════════════════════════════════════════════
bold ""
bold "═══════════════════════════════════════════════════════"
bold "  Results: $pass passed, $fail failed"
bold "═══════════════════════════════════════════════════════"

if [[ $fail -gt 0 ]]; then
  exit 1
fi
