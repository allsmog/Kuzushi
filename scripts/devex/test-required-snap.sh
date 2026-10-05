#!/usr/bin/env bash
set -euo pipefail

# Exercise the real directive loop with a deterministic terminal capture adapter.
. "$(cd "$(dirname "$0")" && pwd)/run-journey.sh"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/kuzushi-required-snap.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT
RUN_SIZE=80x24 SIZE_OVERRIDE="" KUZUSHI_BIN=/bin/true
ensure_session() { :; }
devex_session_kill() { :; }
write_snapshot_provenance() { printf '{}\n' > "$PENDING_META"; }
capture_pending() {
  [ "$1" != live ] || [ "$TEST_SURFACE" = live ] || return 1
  printf '%s\n' "$TEST_SCREEN" > "$PENDING_SNAP"
  cp "$PENDING_SNAP" "$PENDING_ANSI"
}

check_journey() { # <case> <directive> <surface> <screen> <exit> <continues>
  local label=$1 directive=$2 expected_exit=$5 expected_continuation=$6 rc=0
  TEST_SURFACE=$3 TEST_SCREEN=$4
  local recipe="$TEST_ROOT/$label.journey" marker="$TEST_ROOT/$label.ran"
  printf '%s: 0 Ready | prerequisite\nshell: touch %s\n' \
    "$directive" "$marker" > "$recipe"
  run_journey "$recipe" "$TEST_ROOT/runs" > "$TEST_ROOT/$label.log" || rc=$?
  [ "$rc" -eq "$expected_exit" ] || { cat "$TEST_ROOT/$label.log"; return 1; }
  local continued=no
  [ ! -f "$marker" ] || continued=yes
  [ "$continued" = "$expected_continuation" ] || return 1
  if [ "$expected_exit" -ne 0 ]; then
    [ "$FAIL_N" -eq 1 ] && [ -z "$LAST_SNAP" ] || return 1
    [ -f "$TEST_ROOT/runs/$label/01-prerequisite.timeout.txt" ] || return 1
  else
    [ -f "$LAST_SNAP" ] && [ "$FAIL_N" -eq 0 ] || return 1
  fi
}

check_journey missing require-live-snap live Waiting 1 no
check_journey saved require-live-snap saved Ready 1 no
check_journey ready require-live-snap live Ready 0 yes
check_journey diagnostic wait-live-snap live Waiting 1 yes
printf 'PASS: required live state stops later actions; success and diagnostic waits retain continuation\n'

recipe="$TEST_ROOT/shell-failure.journey"
marker="$TEST_ROOT/shell-failure.ran"
printf 'require-shell: false\nshell: touch %s\n' "$marker" > "$recipe"
rc=0
run_journey "$recipe" "$TEST_ROOT/runs" > "$TEST_ROOT/shell-failure.log" || rc=$?
[ "$rc" -eq 1 ] && [ ! -e "$marker" ] || { cat "$TEST_ROOT/shell-failure.log"; exit 1; }
printf 'PASS: failed required shell prerequisite prevents later actions\n'

# The real submit directive must stop after an unreadable/corrupted draft.
(
  tmux() { [ "$1" != capture-pane ] || printf 'kz/sast> corrupted\n'; }
  sleep() { :; }
  recipe="$TEST_ROOT/submit-failure.journey"
  marker="$TEST_ROOT/submit-failure.ran"
  printf 'submit: options sast:scan\nshell: touch %s\n' "$marker" > "$recipe"
  rc=0
  run_journey "$recipe" "$TEST_ROOT/runs" > "$TEST_ROOT/submit-failure.log" || rc=$?
  [ "$rc" -eq 1 ] && [ ! -e "$marker" ] || { cat "$TEST_ROOT/submit-failure.log"; exit 1; }
)
printf 'PASS: failed submit prevents dependent actions\n'
