#!/usr/bin/env bash
# kuzushi-master-gate.sh — master acceptance gate (master contract §24).
#
#   ./scripts/devex/kuzushi-master-gate.sh \
#     --cycle baseline|harness|inventory|holistic|evidence|provider|patch|visual|all \
#     --mode  baseline|fast|full|live|stress|parity
#
# Reads: KUZUSHI_DEVEX_TARGET (required), KUZUSHI_MONOREPO_ALIAS (optional),
#        KUZUSHI_PARITY_TARGET / KUZUSHI_PARITY_ALIAS (optional).
# Never clones/copies/worktrees the target.
#
# One implementation of the target-safety plumbing lives in
# local-monorepo-gate.sh (target validation, drift checkpoints, .kuzushi
# state inventory, journey execution, provenance). This wrapper owns:
#   * the --cycle → tests/journeys routing (via GATE_FAST_TESTS /
#     GATE_FAST_JOURNEYS / GATE_FULL_JOURNEYS env consumed by the local gate);
#   * the §13.A static unsafe-directive audit over every journey that a
#     selected cycle would execute (destructive target operations are
#     SAFETY-BLOCKED, never run);
#   * stress-mode cells (honest PENDING failure where a cycle has none yet).
set -uo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
LOCAL_GATE="$REPO_ROOT/scripts/devex/local-monorepo-gate.sh"
JOURNEY_DIR="$REPO_ROOT/scripts/devex/journeys"
# shellcheck source=scripts/devex/lib.sh
. "$REPO_ROOT/scripts/devex/lib.sh"

CYCLE="" MODE=""
while [ $# -gt 0 ]; do
  case $1 in
    --cycle) CYCLE=${2:-}; shift 2 ;;
    --mode)  MODE=${2:-};  shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
case $CYCLE in
  baseline|harness|inventory|holistic|evidence|provider|patch|visual|all) ;;
  *) echo "usage: --cycle baseline|harness|inventory|holistic|evidence|provider|patch|visual|all --mode baseline|fast|full|live|stress|parity" >&2; exit 2 ;;
esac
case $MODE in
  baseline|fast|full|live|stress|parity) ;;
  *) echo "unknown --mode: $MODE" >&2; exit 2 ;;
esac

FAILED=0
REVIEW_REQUIRED=0
note() { printf 'master-gate: %s\n' "$*"; }
flunk() { FAILED=1; note "FAIL: $*"; }

# ---------------------------------------------------------------- cycle routing
# Per-cycle focused test filters (cargo test -p suffixes, newline separated)
# and journey sets. Journeys must exist and pass the safety audit below.
tests_for_cycle() {
  case $1 in
    harness)   echo "" ;;
    inventory) printf '%s\n' \
      "kuzushi-core --lib workspace::inventory" \
      "kuzushi-core --lib workspace::application::nested_scope" \
      "kuzushi-core --lib modules::context" ;;
    holistic)  printf '%s\n' \
      "kuzushi-core --lib workspace::coverage_ledger" \
      "kuzushi-core --lib capabilities::scan_recommender" \
      "kuzushi-core --lib workflow_attempts" ;;
    evidence)  printf '%s\n' \
      "kuzushi-core --lib capabilities::chains" \
      "kuzushi-core --lib findings" ;;
    provider)  printf '%s\n' \
      "kuzushi-core --lib runtime::policy" \
      "kuzushi-core --lib modules::runtime_requirements" ;;
    patch)     printf '%s\n' \
      "kuzushi-core --lib capabilities::patch" \
      "kuzushi-core --lib run_lifecycle" ;;
    visual)    printf '%s\n' \
      "kuzushi-tui --lib renderer" \
      "kuzushi-tui --lib ui_view_models" ;;
    all)       for c in harness inventory holistic evidence provider patch visual; do tests_for_cycle "$c"; done ;;
  esac
}
fast_journeys_for_cycle() {
  case $1 in
    harness)   echo "J17" ;;      # canonical reference; FAILS until G10 repaired — honest
    inventory) echo "J25" ;;
    holistic)  echo "J25" ;;
    evidence)  echo "J21" ;;
    provider)  echo "J24" ;;
    patch)     echo "J24" ;;
    visual)    echo "J25" ;;
    all)       echo "J17 J21 J24 J25" ;;
  esac
}
full_journeys_for_cycle() {
  case $1 in
    harness)   echo "J17 J25" ;;
    inventory) echo "J25 J26 J27" ;;
    holistic)  echo "J25 J26 J27 J29" ;;
    evidence)  echo "J21 J22 J23" ;;
    provider)  echo "J24" ;;
    patch)     echo "J24" ;;
    visual)    echo "J17 J25" ;;
    all)       echo "J17 J21 J22 J23 J24 J25 J26 J27 J29" ;;
  esac
}

# ---------------------------------------------------------------- §13.A safety audit
# Reject destructive target operations statically, before any execution.
# A journey that mutates @TARGET (delete .kuzushi, reset/clean/checkout/
# stash/rebase, write into target source) is SAFETY-BLOCKED.
audit_journey_safety() { # <journey ids...>
  local unsafe=0 file
  for j in "$@"; do
    file=$(ls "$JOURNEY_DIR"/"$j"-*.journey 2>/dev/null | head -1)
    if [ -z "$file" ]; then
      flunk "journey $j not found in $JOURNEY_DIR"
      unsafe=1
      continue
    fi
    if grep -nE 'rm[[:space:]]+(-[a-zA-Z]+[[:space:]]+)*"?@TARGET|git[[:space:]]+-C[[:space:]]+"?@TARGET"?[[:space:]]+(reset|clean|checkout|stash|rebase|switch)|>[[:space:]]*"?@TARGET' "$file" >/dev/null; then
      flunk "SAFETY-BLOCKED journey $j — destructive target directive:"
      grep -nE 'rm[[:space:]]+(-[a-zA-Z]+[[:space:]]+)*"?@TARGET|git[[:space:]]+-C[[:space:]]+"?@TARGET"?[[:space:]]+(reset|clean|checkout|stash|rebase|switch)|>[[:space:]]*"?@TARGET' "$file" | sed 's/^/    /'
      unsafe=1
    fi
  done
  return $unsafe
}

# The harness-truth cell audits the WHOLE catalog, not just the journeys a
# cycle executes: an unsafe journey on disk is a live hazard regardless of
# routing. Runs for --cycle harness|all in fast/full modes.
audit_whole_catalog() {
  local hits
  hits=$(grep -lnE 'rm[[:space:]]+(-[a-zA-Z]+[[:space:]]+)*"?@TARGET|git[[:space:]]+-C[[:space:]]+"?@TARGET"?[[:space:]]+(reset|clean|checkout|stash|rebase|switch)' \
    "$JOURNEY_DIR"/*.journey 2>/dev/null || true)
  if [ -n "$hits" ]; then
    while IFS= read -r f; do
      flunk "SAFETY: destructive target directive present in $(basename "$f")"
    done <<< "$hits"
  else
    note "PASS catalog safety audit (no destructive target directives)"
  fi
}

# ---------------------------------------------------------------- modes
delegate() { # <local-gate mode> [extra args]
  local mode=$1 rc=0; shift || true
  GATE_FAST_TESTS="$FAST_TESTS" \
  GATE_FAST_JOURNEYS="$FAST_JOURNEYS" \
  GATE_FULL_JOURNEYS="$FULL_JOURNEYS" \
    "$LOCAL_GATE" "$mode" "$@" || rc=$?
  case $rc in
    0) ;;
    "$DEVEX_REVIEW_REQUIRED_EXIT") REVIEW_REQUIRED=1;;
    *) FAILED=1;;
  esac
}

FAST_TESTS=$(tests_for_cycle "$CYCLE")
FAST_JOURNEYS=$(fast_journeys_for_cycle "$CYCLE")
FULL_JOURNEYS=$(full_journeys_for_cycle "$CYCLE")

note "cycle=$CYCLE mode=$MODE"
note "target: ${KUZUSHI_DEVEX_TARGET:-<unset — local gate will refuse>}"

case $MODE in
  baseline)
    # Immutable current-behavior recording; the local gate's --baseline
    # already records provenance/state and runs journeys record-only.
    # shellcheck disable=SC2086
    audit_journey_safety $FULL_JOURNEYS || note "unsafe journeys excluded from execution by routing"
    delegate --baseline
    ;;
  fast)
    case $CYCLE in harness|all) audit_whole_catalog ;; esac
    # shellcheck disable=SC2086
    audit_journey_safety $FAST_JOURNEYS || true   # audit failures already flunked
    [ $FAILED -eq 0 ] && delegate --fast
    ;;
  full)
    case $CYCLE in harness|all) audit_whole_catalog ;; esac
    # shellcheck disable=SC2086
    audit_journey_safety $FULL_JOURNEYS || true
    [ $FAILED -eq 0 ] && delegate --full
    ;;
  live)
    delegate --live
    ;;
  parity)
    if [ -n "${KUZUSHI_PARITY_TARGET:-}" ]; then
      delegate --parity "$KUZUSHI_PARITY_TARGET"
    else
      note "SKIP parity: KUZUSHI_PARITY_TARGET not supplied (no second existing checkout)"
    fi
    ;;
  stress)
    case $CYCLE in
      inventory|all)
        note "stress[inventory]: throughput probe against the real target (read-only)"
        if [ -z "${KUZUSHI_DEVEX_TARGET:-}" ]; then
          flunk "stress requires KUZUSHI_DEVEX_TARGET"
        elif KUZUSHI_INVENTORY_PROBE_ROOT="$KUZUSHI_DEVEX_TARGET" \
             cargo test -p kuzushi-core --lib inventory_throughput_probe -- --ignored --nocapture; then
          note "PASS stress inventory probe"
        else
          flunk "stress inventory probe"
        fi
        ;;
    esac
    case $CYCLE in
      inventory) : ;;
      *)
        # Honest disclosure: stress cells for the other cycles are campaign
        # work not yet implemented (generated ScopeGraph scale fixtures,
        # cancellation/resume stress, counter assertions).
        flunk "STRESS CELLS PENDING for cycle '$CYCLE' — not implemented yet (campaign incomplete)"
        ;;
    esac
    ;;
esac

if [ $FAILED -ne 0 ]; then
  note "verdict: FAILED (cycle=$CYCLE mode=$MODE)"
  exit 1
elif [ $REVIEW_REQUIRED -ne 0 ]; then
  note "verdict: REVIEW REQUIRED (cycle=$CYCLE mode=$MODE)"
  exit "$DEVEX_REVIEW_REQUIRED_EXIT"
else
  note "verdict: CLEAN (cycle=$CYCLE mode=$MODE)"
fi
exit 0
