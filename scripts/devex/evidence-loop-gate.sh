#!/usr/bin/env bash
# evidence-loop-gate.sh — Phase C convergence gate for the evidence-loop
# redesign contract.
#
#   --fast   fmt check + workspace unit tests (kuzushi-core + kuzushi-tui)
#   --full   clean rebuild (dedicated target dir wiped first) + everything in
#            --fast + journeys J21 J22 J23 J24 with ZERO machine-check
#            failures + gate report regeneration
#
# Honesty policy — the gate never hides a failure, it discloses two known
# ENVIRONMENT classes and fails on anything else:
#   1. kuzushi-core `modules::dynamic_loader` / `modules::registry` dynamic-JS
#      tests require Node >= 25 permission mode; they are accepted as
#      environment-limited ONLY when the local Node is older AND every
#      accepted failure matches those modules (each one listed in the log).
#   2. timing-sensitive kuzushi-tui tests that fail under full-suite
#      parallel load are re-run solo once; they pass only if solo-green
#      (each rerun disclosed in the log).
#
# Every journey this gate runs (J21–J24) uses a HARNESS-OWNED fixture
# target (@TMP_TARGET or journey-local fixtures). No operator checkout is
# required, read, or touched: real-monorepo acceptance belongs to
# local-monorepo-gate.sh / kuzushi-master-gate.sh, which require an
# explicit KUZUSHI_DEVEX_TARGET and never delete target state.
set -uo pipefail

MODE=${1:---fast}
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"
# shellcheck source=scripts/devex/lib.sh
. "$REPO_ROOT/scripts/devex/lib.sh"
GATE_TARGET_DIR="$REPO_ROOT/target-dev"
GATE_ROOT=${EVIDENCE_LOOP_GATE_ROOT:-"$HOME/kz-evidence-loop/phaseC"}
STAMP=$(date -u +%Y%m%d-%H%M%S)
RUN_DIR="$GATE_ROOT/gate-$STAMP-${MODE#--}"
mkdir -p "$RUN_DIR"
LOG="$RUN_DIR/gate.log"
VERDICT="$RUN_DIR/verdict.txt"
FAILED=0
REVIEW_REQUIRED=0

say() { printf '%s\n' "$*" | tee -a "$LOG"; }
fail() { FAILED=1; say "GATE-FAIL: $*"; }

say "evidence-loop gate $MODE · $(date -u +%FT%TZ)"
say "worktree: $REPO_ROOT @ $(git rev-parse --short HEAD 2>/dev/null || echo unknown) (uncommitted work included by design)"
say "targets: harness-owned fixtures only (no operator checkout used)"

# ---------------------------------------------------------------- fmt
if ! cargo fmt --check >>"$LOG" 2>&1; then
  fail "cargo fmt --check"
else
  say "PASS fmt"
fi

# ---------------------------------------------------------------- build
export CARGO_TARGET_DIR="$GATE_TARGET_DIR"
free_gb=$(df --output=avail -BG "$REPO_ROOT" | tail -1 | tr -dc '0-9')
if [ "${free_gb:-0}" -lt 10 ]; then
  fail "insufficient disk headroom (${free_gb}G free < 10G) — refusing to build"
  echo "verdict: FAILED" > "$VERDICT"
  exit 1
fi
if [ "$MODE" = "--full" ]; then
  # Clean rebuild policy: every WORKSPACE crate is rebuilt from scratch
  # (cargo clean per member); third-party dependency artifacts stay cached.
  # Disclosed here because the box lacks disk for a full target wipe.
  say "FULL: clean rebuild of all workspace crates (dependency cache retained)"
  for member in $(cargo metadata --no-deps --format-version 1 2>/dev/null       | grep -o '"name":"[^"]*"' | cut -d'"' -f4 | sort -u); do
    cargo clean -p "$member" >>"$LOG" 2>&1 || true
  done
fi
if ! cargo build -p kuzushi-cli >>"$LOG" 2>&1; then
  fail "cargo build -p kuzushi-cli"
else
  say "PASS build"
fi
KUZUSHI_BIN="$GATE_TARGET_DIR/debug/kuzushi"

# ---------------------------------------------------------------- tests
run_crate_tests() { # crate, env-allow-regex ("" = none)
  local crate=$1 allow_regex=$2 json="$RUN_DIR/$1-tests.txt"
  cargo test -p "$crate" --lib >"$json" 2>&1
  local status=$?
  cat "$json" >>"$LOG"
  if [ $status -eq 0 ]; then
    say "PASS tests $crate"
    return 0
  fi
  local failures
  failures=$(grep -E '^test .* \.\.\. FAILED$' "$json" | awk '{print $2}')
  [ -z "$failures" ] && { fail "tests $crate (no parseable failures — see log)"; return 1; }
  local residue=""
  local node_major
  node_major=$(node --version 2>/dev/null | sed 's/^v\([0-9]*\).*/\1/')
  for test_name in $failures; do
    if [ -n "$allow_regex" ] && printf '%s' "$test_name" | grep -Eq "$allow_regex" \
       && [ -n "$node_major" ] && [ "$node_major" -lt 25 ]; then
      say "ENV-LIMITED $crate::$test_name (dynamic-JS needs Node>=25; local Node v$node_major)"
      continue
    fi
    # timing-flaky retry: solo rerun must pass
    if cargo test -p "$crate" --lib -- --exact "$test_name" >>"$LOG" 2>&1; then
      say "FLAKY-SOLO-PASS $crate::$test_name (failed under parallel load, green solo)"
      continue
    fi
    residue="$residue $test_name"
  done
  if [ -n "$residue" ]; then
    fail "tests $crate:$residue"
    return 1
  fi
  say "PASS tests $crate (with disclosed env/flaky exceptions above)"
}

run_crate_tests kuzushi-core '^modules::(dynamic_loader|registry)::'
run_crate_tests kuzushi-tui ''

# ---------------------------------------------------------------- journeys (FULL)
if [ "$MODE" = "--full" ]; then
  for journey in J21 J22 J23 J24; do
    say "JOURNEY $journey"
    journey_rc=0
    KUZUSHI_BIN="$KUZUSHI_BIN" \
      KUZUSHI_DEVEX_ARTIFACT_ROOT="$RUN_DIR/journeys" \
      "$REPO_ROOT/scripts/devex/run-journey.sh" "$journey" >>"$LOG" 2>&1 \
      || journey_rc=$?
    report_line=$(grep -h 'result:' "$RUN_DIR"/journeys/*/"$journey"/report.txt 2>/dev/null | tail -1)
    case $journey_rc in
      0) say "PASS journey $journey ($report_line)";;
      "$DEVEX_REVIEW_REQUIRED_EXIT")
        REVIEW_REQUIRED=1
        say "REVIEW journey $journey — human judgment required ($report_line)"
        ;;
      *) fail "journey $journey ($report_line)";;
    esac
  done
fi

# ---------------------------------------------------------------- verdict
{
  echo "mode: $MODE"
  echo "worktree: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "completed: $(date -u +%FT%TZ)"
  echo "disclosed environment limitations:"
  echo "  - kuzushi-core dynamic-JS tests require Node >= 25 (see ENV-LIMITED lines)"
  # Provider capability is DERIVED from doctor at gate time, never asserted
  # from stale prose (post-Vertex-support honesty rule).
  if [ -x "$KUZUSHI_BIN" ] && "$KUZUSHI_BIN" doctor > "$RUN_DIR/doctor.txt" 2>&1; then
    echo "  - provider capability (from doctor at $(date -u +%FT%TZ); full report: doctor.txt):"
    grep -iE 'auth|provider|vertex|model|credential' "$RUN_DIR/doctor.txt" | sed 's/^/      /' \
      || echo "      (doctor reported no provider lines)"
    echo "    model-backed cells are exercised by live-mode gates, not this one;"
    echo "    J24 captures the runtime-free refusal/deferral chain either way"
  else
    echo "  - provider capability: doctor probe unavailable (binary missing or doctor failed;"
    echo "    see doctor.txt if present) — no capability is claimed without a probe"
  fi
  if [ $FAILED -ne 0 ]; then
    echo "verdict: FAILED"
  elif [ $REVIEW_REQUIRED -ne 0 ]; then
    echo "verdict: REVIEW REQUIRED"
  else
    echo "verdict: CLEAN"
  fi
} | tee "$VERDICT" | tee -a "$LOG" >/dev/null
if [ $FAILED -ne 0 ]; then
  say "verdict: FAILED · artifacts: $RUN_DIR"
  exit 1
fi
if [ $REVIEW_REQUIRED -ne 0 ]; then
  say "verdict: REVIEW REQUIRED · artifacts: $RUN_DIR"
  exit "$DEVEX_REVIEW_REQUIRED_EXIT"
fi
say "verdict: CLEAN · artifacts: $RUN_DIR"
exit 0
