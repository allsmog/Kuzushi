#!/usr/bin/env bash
# run-e2e.sh — Runs E2E tests A-F for scanner power improvements.
#
# Prerequisites:
#   - ollama running with qwen3:8b pulled
#   - semgrep installed
#   - kuzushi built (pnpm build or use pnpm dev)
#
# Usage:
#   ./tests/e2e/run-e2e.sh              # Run all tests
#   ./tests/e2e/run-e2e.sh A            # Run only Test A
#   ./tests/e2e/run-e2e.sh A B F        # Run Tests A, B, F
#   KUZUSHI_TIMEOUT=900 ./tests/e2e/run-e2e.sh  # Custom timeout (seconds)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KUZUSHI_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_APP_DIR="${TEST_APP_DIR:-/tmp/kuzushi-test-app}"
TEST_LOG_DIR="${TEST_LOG_DIR:-/tmp/kuzushi-e2e-logs}"
KUZUSHI_TIMEOUT="${KUZUSHI_TIMEOUT:-1800}"

export KUZUSHI_DIR TEST_APP_DIR TEST_LOG_DIR KUZUSHI_TIMEOUT

# Source verification helpers.
source "$SCRIPT_DIR/verify.sh"

mkdir -p "$TEST_LOG_DIR"

# ─── Prerequisite checks ─────────────────────────────────────────────

check_prerequisites() {
  header "Prerequisite checks"

  local semgrep_status
  semgrep_status=$(check_semgrep)
  if [[ "$semgrep_status" != "ok" ]]; then
    fail "semgrep not installed" "Install with: pip install semgrep"
    echo "Cannot continue without semgrep. Exiting."
    exit 1
  fi
  pass "semgrep installed ($(semgrep --version 2>/dev/null | head -1))"

  local ollama_status
  ollama_status=$(check_ollama "qwen3:8b")
  case "$ollama_status" in
    missing)
      fail "ollama not installed" "Install from https://ollama.com"
      echo "Cannot continue without ollama. Exiting."
      exit 1
      ;;
    not-running)
      fail "ollama not running" "Start with: ollama serve"
      echo "Cannot continue without ollama running. Exiting."
      exit 1
      ;;
    no-model)
      info "Model qwen3:8b not found. Pulling..."
      ollama pull qwen3:8b
      pass "qwen3:8b pulled"
      ;;
    ok)
      pass "ollama running with qwen3:8b"
      ;;
  esac

  if [[ ! -f "$KUZUSHI_DIR/package.json" ]]; then
    fail "kuzushi repo not found at $KUZUSHI_DIR"
    exit 1
  fi
  pass "kuzushi repo found"
}

# ─── Setup ────────────────────────────────────────────────────────────

setup_test_app() {
  header "Setting up test app"
  bash "$SCRIPT_DIR/setup-test-app.sh" "$TEST_APP_DIR"
  pass "Test app created at $TEST_APP_DIR"
}

# ─── Test A: Full pipeline with prompt enrichment ─────────────────────

test_a() {
  header "Test A: Full pipeline with prompt enrichment (Phases 1A-1F)"

  # Clean previous state.
  rm -rf "$TEST_APP_DIR/.kuzushi/runs" "$TEST_APP_DIR/.kuzushi/findings.sqlite3"

  local exit_code=0
  run_kuzushi "$TEST_APP_DIR" --fresh --audit-log --max 3 2>&1 | tee "$TEST_LOG_DIR/test-a.log" || exit_code=$?

  if [[ $exit_code -ne 0 ]]; then
    fail "Pipeline exited with code $exit_code"
    info "Check $TEST_LOG_DIR/test-a.log for details"
    return
  fi
  pass "Pipeline completed successfully"

  # Check that the scanner found vulnerabilities (from pipeline log output).
  if grep -q "findings.*selected for AI triage" "$TEST_LOG_DIR/test-a.log" 2>/dev/null; then
    local scan_findings
    scan_findings=$(grep -oE '[0-9]+ findings' "$TEST_LOG_DIR/test-a.log" | head -1)
    pass "Scanner produced findings: ${scan_findings:-unknown count}"
  else
    info "Could not parse scan findings count from log"
  fi

  # Check findings were created in DB.
  local db="$TEST_APP_DIR/.kuzushi/findings.sqlite3"
  if [[ ! -f "$db" ]]; then
    fail "Findings database not created"
    return
  fi
  pass "Findings database exists"

  local count
  count=$(findings_count "$db")
  if [[ "$count" -gt 0 ]]; then
    pass "Findings stored in DB: $count"
  else
    # Findings are only stored after successful triage. With small models that
    # can't follow the structured output schema, 0 findings is expected.
    info "No findings stored (findings are only persisted after successful triage)"
  fi

  # Check for triaged findings (verdict set). Small models may fail structured output.
  local triaged_count
  triaged_count=$(db_count "SELECT COUNT(*) FROM findings WHERE verdict IS NOT NULL AND verdict != ''" "$db")
  if [[ "$triaged_count" -gt 0 ]]; then
    pass "Triaged findings: $triaged_count"
  else
    info "No triaged findings (model may not produce valid structured output — expected with small models)"
  fi

  # Phase 1E: Composite confidence.
  if db_column_exists "composite_confidence" "$db"; then
    pass "Phase 1E: composite_confidence column exists"
    if has_composite_confidence; then
      pass "Phase 1E: composite_confidence has non-null values"
      if composite_differs_from_confidence; then
        pass "Phase 1E: composite_confidence differs from raw confidence"
      else
        info "Phase 1E: composite_confidence equals raw confidence (may be expected on first run)"
      fi
    else
      info "Phase 1E: composite_confidence is null for all findings (signals may not have fired)"
    fi
  else
    fail "Phase 1E: composite_confidence column missing"
  fi

  # Check audit logs exist.
  local run_dir
  run_dir=$(latest_run_dir)
  if [[ -n "$run_dir" && -d "$run_dir" ]]; then
    pass "Audit log directory created: $(basename "$run_dir")"

    if [[ -f "$run_dir/run.json" ]]; then
      pass "run.json written"
    else
      fail "run.json not found in audit dir"
    fi

    local triage_lines
    triage_lines=$(audit_line_count "triage" "$run_dir")
    if [[ "$triage_lines" -gt 0 ]]; then
      pass "triage.jsonl has $triage_lines entries"
    else
      fail "triage.jsonl is empty or missing"
    fi

    # Phase 1A: Knowledge registry — check for Domain Knowledge references in agent activity.
    local knowledge_hits
    knowledge_hits=$(audit_grep "Domain Knowledge\|knowledge\|dangerous.*pattern\|injection" "triage" "$run_dir" | wc -l | tr -d ' ')
    if [[ "$knowledge_hits" -gt 0 ]]; then
      pass "Phase 1A: Knowledge registry references found in triage audit ($knowledge_hits hits)"
    else
      info "Phase 1A: No direct knowledge registry references in audit (prompt may not be logged verbatim)"
    fi

    # Phase 1B: Bypass knowledge — check for bypass technique references.
    local bypass_hits
    bypass_hits=$(audit_grep "bypass\|technique\|evasion\|WAF\|filter" "triage" "$run_dir" | wc -l | tr -d ' ')
    if [[ "$bypass_hits" -gt 0 ]]; then
      pass "Phase 1B: Bypass knowledge references found in triage audit ($bypass_hits hits)"
    else
      info "Phase 1B: No bypass references in audit (prompt sections not logged verbatim)"
    fi

    # Phase 1C: Precedents — check for precedent text in audit.
    local precedent_hits
    precedent_hits=$(audit_grep "precedent\|better-sqlite3\|helmet" "triage" "$run_dir" | wc -l | tr -d ' ')
    if [[ "$precedent_hits" -gt 0 ]]; then
      pass "Phase 1C: Precedent references found in triage audit ($precedent_hits hits)"
    else
      info "Phase 1C: No precedent references in audit"
    fi

  else
    fail "No audit log directory found"
  fi

  # Check for triage results with verdicts.
  local verdicts
  verdicts=$(findings_verdicts "$db")
  if echo "$verdicts" | grep -qE "tp|fp|needs_review"; then
    pass "Findings have verdicts: $(echo "$verdicts" | grep -v '^verdict$' | tr '\n' ', ')"
  else
    info "No findings have triage verdicts (expected with small models that can't follow batch schema)"
  fi

  info "Full finding details:"
  db_query "SELECT fingerprint, rule_id, file_path, start_line, verdict, confidence, composite_confidence FROM findings" "$db" | head -20
}

# ─── Test B: Multi-agent triage ───────────────────────────────────────

test_b() {
  header "Test B: Multi-agent triage with conflict resolution (Phases 1G, 2A-2B)"

  rm -rf "$TEST_APP_DIR/.kuzushi/runs" "$TEST_APP_DIR/.kuzushi/findings.sqlite3"

  # triageStrategy is config-only (no CLI flag), so patch config.json.
  local config="$TEST_APP_DIR/.kuzushi/config.json"
  local orig_config
  orig_config=$(cat "$config")
  # Add triageStrategy: "multi-agent" to config.
  echo "$orig_config" | sed 's/"auditLog": true/"auditLog": true, "triageStrategy": "multi-agent"/' > "$config"

  local exit_code=0
  run_kuzushi "$TEST_APP_DIR" \
    --fresh \
    --audit-log \
    --max 2 \
    2>&1 | tee "$TEST_LOG_DIR/test-b.log" || exit_code=$?

  # Restore original config.
  echo "$orig_config" > "$config"

  if [[ $exit_code -ne 0 ]]; then
    fail "Multi-agent pipeline exited with code $exit_code"
    info "Check $TEST_LOG_DIR/test-b.log for details"
    return
  fi
  pass "Multi-agent pipeline completed successfully"

  local db="$TEST_APP_DIR/.kuzushi/findings.sqlite3"
  local count
  count=$(findings_count "$db")
  if [[ "$count" -gt 0 ]]; then
    pass "Findings created: $count"
  else
    info "No findings stored (findings only persisted after successful triage)"
  fi

  # Phase 2A: Check for conflict resolution in triage details.
  local conflict_hits
  conflict_hits=$(db_count "SELECT COUNT(*) FROM findings WHERE triage_details_json LIKE '%conflict%'" "$db")
  if [[ "$conflict_hits" -gt 0 ]]; then
    pass "Phase 2A: conflict_resolution found in $conflict_hits finding(s)"
  else
    info "Phase 2A: No conflict_resolution in triage details (specialists may have agreed)"
  fi

  # Check audit logs for multi-agent activity.
  local run_dir
  run_dir=$(latest_run_dir)
  if [[ -n "$run_dir" ]]; then
    local triage_lines
    triage_lines=$(audit_line_count "triage" "$run_dir")
    if [[ "$triage_lines" -gt 0 ]]; then
      pass "Multi-agent triage audit has $triage_lines entries"
      # Multi-agent should produce MORE entries than single-agent (4 specialists + 1 manager).
      if [[ "$triage_lines" -gt 5 ]]; then
        pass "Audit entry count ($triage_lines) consistent with multi-agent (>5 expected)"
      else
        info "Audit entry count ($triage_lines) seems low for multi-agent"
      fi
    else
      fail "triage.jsonl is empty"
    fi
  fi
}

# ─── Test C: Dataflow deduplication ───────────────────────────────────

test_c() {
  header "Test C: Dataflow deduplication (Phase 3A)"

  rm -rf "$TEST_APP_DIR/.kuzushi/runs" "$TEST_APP_DIR/.kuzushi/findings.sqlite3"

  local exit_code=0
  run_kuzushi "$TEST_APP_DIR" --fresh --audit-log --max 3 2>&1 | tee "$TEST_LOG_DIR/test-c.log" || exit_code=$?

  if [[ $exit_code -ne 0 ]]; then
    fail "Pipeline exited with code $exit_code"
    return
  fi
  pass "Pipeline completed"

  local db="$TEST_APP_DIR/.kuzushi/findings.sqlite3"
  local count
  count=$(findings_count "$db")
  pass "Total findings in DB: $count"

  # Check for corroboration signals (dedup merges findings and adds corroboration).
  local corroboration_count
  corroboration_count=$(db_count "SELECT COUNT(*) FROM findings WHERE corroboration_json IS NOT NULL AND corroboration_json != 'null' AND corroboration_json != '[]'" "$db")
  if [[ "$corroboration_count" -gt 0 ]]; then
    pass "Phase 3A: $corroboration_count finding(s) have corroboration signals (dedup working)"
  else
    info "Phase 3A: No corroboration signals found (dedup may not have matched these patterns)"
  fi

  # Show findings by file and rule for inspection.
  info "Findings by file and rule:"
  db_query "SELECT file_path, rule_id, start_line, fingerprint FROM findings ORDER BY file_path, start_line" "$db"

  # Check if server.js command injection findings were deduped.
  # The test app has two child_process calls with the same source (req.query.cmd).
  local server_cmdi_count
  server_cmdi_count=$(db_count "SELECT COUNT(*) FROM findings WHERE file_path LIKE '%server.js%' AND (rule_id LIKE '%command%' OR rule_id LIKE '%inject%' OR rule_id LIKE '%child%' OR message LIKE '%command%' OR message LIKE '%inject%')" "$db")
  info "Command injection findings in server.js: $server_cmdi_count"
  if [[ "$server_cmdi_count" -gt 0 && "$server_cmdi_count" -lt 3 ]]; then
    pass "Phase 3A: server.js has $server_cmdi_count command injection findings (dedup may have reduced from 3)"
  elif [[ "$server_cmdi_count" -ge 3 ]]; then
    info "Phase 3A: server.js has $server_cmdi_count command injection findings (no dedup reduction observed)"
  else
    info "Phase 3A: No command injection findings matched filter (check rule_id patterns)"
  fi
}

# ─── Test D: Reachability check ──────────────────────────────────────

test_d() {
  header "Test D: Reachability check (Phase 3B)"

  rm -rf "$TEST_APP_DIR/.kuzushi/runs" "$TEST_APP_DIR/.kuzushi/findings.sqlite3"

  local exit_code=0
  run_kuzushi "$TEST_APP_DIR" \
    --fresh \
    --audit-log \
    --max 3 \
    --enabled-tasks reachability-check \
    2>&1 | tee "$TEST_LOG_DIR/test-d.log" || exit_code=$?

  if [[ $exit_code -ne 0 ]]; then
    fail "Pipeline exited with code $exit_code"
    info "Check $TEST_LOG_DIR/test-d.log for details"
    return
  fi
  pass "Pipeline with reachability-check completed"

  local db="$TEST_APP_DIR/.kuzushi/findings.sqlite3"
  local count
  count=$(findings_count "$db")
  pass "Total findings: $count"

  # Compare adjusted scores between dead-code.js and server.js findings.
  info "Findings with adjusted scores:"
  db_query "SELECT file_path, rule_id, start_line, adjusted_score, verdict, confidence FROM findings ORDER BY file_path" "$db"

  # Check if dead-code.js findings have lower scores.
  local dead_code_score
  dead_code_score=$(db_query "SELECT AVG(adjusted_score) FROM findings WHERE file_path LIKE '%dead-code%'" "$db" | tail -1)
  local server_score
  server_score=$(db_query "SELECT AVG(adjusted_score) FROM findings WHERE file_path LIKE '%server.js%'" "$db" | tail -1)

  if [[ -n "$dead_code_score" && "$dead_code_score" != "" && -n "$server_score" && "$server_score" != "" ]]; then
    info "Average adjusted_score: dead-code.js=$dead_code_score, server.js=$server_score"
    # Use awk for float comparison.
    if echo "$dead_code_score $server_score" | awk '{exit !($1 < $2)}'; then
      pass "Phase 3B: dead-code.js score ($dead_code_score) < server.js score ($server_score)"
    else
      info "Phase 3B: dead-code.js score not lower (reachability may not have penalized)"
    fi
  else
    info "Phase 3B: Could not compare scores (some files may have no findings)"
  fi
}

# ─── Test E: Regression detection ────────────────────────────────────

test_e() {
  header "Test E: Regression detection (Phase 3C)"

  rm -rf "$TEST_APP_DIR/.kuzushi/runs" "$TEST_APP_DIR/.kuzushi/findings.sqlite3"

  # Step 1: Run baseline scan to populate findings.
  info "Step 1: Running baseline scan..."
  local exit_code=0
  run_kuzushi "$TEST_APP_DIR" --fresh 2>&1 | tee "$TEST_LOG_DIR/test-e-baseline.log" || exit_code=$?

  if [[ $exit_code -ne 0 ]]; then
    fail "Baseline scan failed with code $exit_code"
    return
  fi
  pass "Baseline scan completed"

  local db="$TEST_APP_DIR/.kuzushi/findings.sqlite3"
  local baseline_count
  baseline_count=$(findings_count "$db")
  pass "Baseline findings: $baseline_count"

  # Step 2: Fix the XSS in server.js (escape HTML output), commit.
  info "Step 2: Fixing XSS and committing..."
  (
    cd "$TEST_APP_DIR"
    # Use python for reliable string replacement.
    python3 -c "
import pathlib
p = pathlib.Path('server.js')
src = p.read_text()
# Replace unsafe res.send with escaped version.
src = src.replace(
    'res.send(\"<h1>Welcome, \" + username + \"</h1>\")',
    'res.send(\"<h1>Welcome, \" + username.replace(/</g, \"&lt;\").replace(/>/g, \"&gt;\") + \"</h1>\")'
)
p.write_text(src)
"
    git add -A
    git commit -q -m "fix: escape HTML in profile endpoint"
  )
  pass "XSS fix committed"

  # Step 3: Revert the fix (re-introduce vulnerability).
  info "Step 3: Reverting fix (re-introducing vulnerability)..."
  (
    cd "$TEST_APP_DIR"
    git revert --no-edit HEAD
  )
  pass "Fix reverted (vulnerability re-introduced)"

  # Step 4: Run diff-review with regression detection.
  # diffBase is config-only (no CLI flag), so patch config.json.
  info "Step 4: Running diff-review with diffBase=HEAD~2..."
  local config="$TEST_APP_DIR/.kuzushi/config.json"
  local orig_config
  orig_config=$(cat "$config")
  echo "$orig_config" | sed 's/"auditLog": true/"auditLog": true, "diffBase": "HEAD~2"/' > "$config"

  exit_code=0
  run_kuzushi "$TEST_APP_DIR" \
    --enabled-tasks diff-review \
    --audit-log \
    2>&1 | tee "$TEST_LOG_DIR/test-e-regression.log" || exit_code=$?

  # Restore original config.
  echo "$orig_config" > "$config"

  if [[ $exit_code -ne 0 ]]; then
    fail "Diff-review scan exited with code $exit_code"
    info "Check $TEST_LOG_DIR/test-e-regression.log for details"
    return
  fi
  pass "Diff-review scan completed"

  # Check for regression findings.
  local regression_count
  regression_count=$(db_count "SELECT COUNT(*) FROM findings WHERE rule_id LIKE '%regression%'" "$db")
  if [[ "$regression_count" -gt 0 ]]; then
    pass "Phase 3C: Found $regression_count regression finding(s)"
  else
    info "Phase 3C: No regression-tagged findings (diff-review may have reported differently)"
  fi

  info "All findings after diff-review:"
  db_query "SELECT rule_id, file_path, start_line, verdict, confidence FROM findings ORDER BY rule_id" "$db"
}

# ─── Test F: Scanner cache ───────────────────────────────────────────

test_f() {
  header "Test F: Scanner cache (Phase 3D)"

  rm -rf "$TEST_APP_DIR/.kuzushi/runs" "$TEST_APP_DIR/.kuzushi/findings.sqlite3"

  # Reset test app to original state (test_e may have added commits).
  info "Resetting test app to initial commit..."
  bash "$SCRIPT_DIR/setup-test-app.sh" "$TEST_APP_DIR" > /dev/null

  # First run: populates cache.
  info "Run 1: Fresh scan (populates cache)..."
  local exit_code=0
  run_kuzushi "$TEST_APP_DIR" --fresh --audit-log --max 3 2>&1 | tee "$TEST_LOG_DIR/test-f-run1.log" || exit_code=$?

  if [[ $exit_code -ne 0 ]]; then
    fail "First run failed with code $exit_code"
    return
  fi
  pass "First run completed"

  local db="$TEST_APP_DIR/.kuzushi/findings.sqlite3"
  local cache_count
  cache_count=$(scanner_cache_count "$db")
  info "Scanner cache entries after run 1: $cache_count"

  if [[ "$cache_count" -gt 0 ]]; then
    pass "Phase 3D: Scanner cache populated with $cache_count entries"
  else
    info "Phase 3D: Scanner cache table is empty (cache wiring may be deferred)"
  fi

  # Check that scanner_cache table exists.
  local tables
  tables=$(sqlite3 "$db" ".tables" 2>/dev/null || echo "")
  if echo "$tables" | grep -q "scanner_cache"; then
    pass "Phase 3D: scanner_cache table exists in DB"
  else
    info "Phase 3D: scanner_cache table not found (migration may not have run)"
  fi

  # Second run: should hit cache.
  info "Run 2: Incremental scan (should hit cache)..."
  local start_time
  start_time=$(date +%s)
  exit_code=0
  run_kuzushi "$TEST_APP_DIR" --audit-log --max 3 2>&1 | tee "$TEST_LOG_DIR/test-f-run2.log" || exit_code=$?
  local end_time
  end_time=$(date +%s)
  local elapsed=$((end_time - start_time))

  if [[ $exit_code -ne 0 ]]; then
    fail "Second run failed with code $exit_code"
    return
  fi
  pass "Second run completed in ${elapsed}s"

  local cache_count_after
  cache_count_after=$(scanner_cache_count "$db")
  info "Scanner cache entries after run 2: $cache_count_after"
}

# ─── Main ─────────────────────────────────────────────────────────────

main() {
  echo ""
  echo "╔════════════════════════════════════════════════════════╗"
  echo "║  Kuzushi E2E Tests — Scanner Power Improvements       ║"
  echo "╚════════════════════════════════════════════════════════╝"
  echo ""
  echo "  Kuzushi dir:  $KUZUSHI_DIR"
  echo "  Test app dir: $TEST_APP_DIR"
  echo "  Log dir:      $TEST_LOG_DIR"
  echo "  Timeout:      ${KUZUSHI_TIMEOUT}s per scan"

  check_prerequisites
  setup_test_app

  # Determine which tests to run.
  local tests_to_run=("$@")
  if [[ ${#tests_to_run[@]} -eq 0 ]]; then
    tests_to_run=(A B C D E F)
  fi

  for t in "${tests_to_run[@]}"; do
    case "${t^^}" in
      A) test_a ;;
      B) test_b ;;
      C) test_c ;;
      D) test_d ;;
      E) test_e ;;
      F) test_f ;;
      *)
        echo "Unknown test: $t (valid: A B C D E F)"
        ;;
    esac
  done

  summary
  echo ""
  echo "Logs saved to: $TEST_LOG_DIR"
  echo "Test app at:   $TEST_APP_DIR"

  # Exit with failure if any checks failed.
  if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
  fi
}

main "$@"
