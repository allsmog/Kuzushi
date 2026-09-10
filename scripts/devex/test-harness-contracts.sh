#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=scripts/devex/lib.sh
. "$SCRIPT_DIR/lib.sh"

assert_eq() { # <expected> <actual> <message>
  if [ "$1" != "$2" ]; then
    printf 'FAIL: %s (expected %s, got %s)\n' "$3" "$1" "$2" >&2
    exit 1
  fi
}

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/kuzushi-devex-contracts.XXXXXX")
cleanup() {
  case $TEST_ROOT in
    "${TMPDIR:-/tmp}"/kuzushi-devex-contracts.*) rm -rf "$TEST_ROOT";;
  esac
}
trap cleanup EXIT INT TERM

assert_eq 'a\\b\"c\td\re\nf' "$(json_escape "$(printf 'a\\b"c\td\re\nf')")" \
  "json_escape escapes backslash, quote, tab, CR and LF"
assert_eq 0 "$(devex_journey_exit_code 0 0)" "clean journey exit"
assert_eq 1 "$(devex_journey_exit_code 1 3)" "machine failure wins over review"
assert_eq 4 "$(devex_journey_exit_code 0 3)" "open review has distinct exit"
assert_eq REVIEW_REQUIRED "$(devex_journey_result_label 0 1)" "open review label"
assert_eq 3 "$(devex_report_review_count 'result: FAIL · 1 pass / 2 fail / 3 review-for-human')" \
  "outer gates preserve review requirements even when machine checks fail"

RETENTION_ROOT="$TEST_ROOT/retention"
mkdir -p "$RETENTION_ROOT"
index=1
while [ "$index" -le 23 ]; do
  run_name=$(printf '202608%02d-120000' "$index")
  mkdir -p "$RETENTION_ROOT/$run_name"
  devex_write_run_result "$RETENTION_ROOT/$run_name" successful 0 0 0
  index=$((index + 1))
done
mkdir -p "$RETENTION_ROOT/20260824-120000" "$RETENTION_ROOT/20260825-120000" \
  "$RETENTION_ROOT/20260826-120000" "$RETENTION_ROOT/20260827-120000"
devex_write_run_result "$RETENTION_ROOT/20260824-120000" failed 1 0 0
devex_write_run_result "$RETENTION_ROOT/20260825-120000" review 0 0 1
devex_write_run_result "$RETENTION_ROOT/20260826-120000" skipped 0 1 0
printf 'legacy evidence\n' > "$RETENTION_ROOT/20260827-120000/report.txt"
ln -s "20260801-120000" "$RETENTION_ROOT/latest"
ln -s "$TEST_ROOT" "$RETENTION_ROOT/20260828-120000"
devex_prune_successful_runs "$RETENTION_ROOT" 20
assert_eq 21 "$(find "$RETENTION_ROOT" -type f -name run-result.json \
  -exec grep -l '"status": "successful"' {} \; | wc -l | tr -d ' ')" \
  "retention keeps newest successful runs plus an older latest target"
[ -d "$RETENTION_ROOT/20260801-120000" ] \
  || { printf 'FAIL: latest successful run was pruned\n' >&2; exit 1; }
[ ! -e "$RETENTION_ROOT/20260802-120000" ] && [ ! -e "$RETENTION_ROOT/20260803-120000" ] \
  || { printf 'FAIL: oldest non-latest successful runs were retained\n' >&2; exit 1; }
for protected in 20260824-120000 20260825-120000 20260826-120000 20260827-120000; do
  [ -d "$RETENTION_ROOT/$protected" ] \
    || { printf 'FAIL: protected run $protected was pruned\n' >&2; exit 1; }
done
[ -L "$RETENTION_ROOT/20260828-120000" ] \
  || { printf 'FAIL: timestamp-shaped symlink was followed or pruned\n' >&2; exit 1; }

printf 'Review is locked\n' > "$TEST_ROOT/wait-screen.txt"
devex_file_contains_any "$TEST_ROOT/wait-screen.txt" \
  'Viewing Review || Review is locked' \
  || { printf 'FAIL: alternate wait did not accept honest lock state\n' >&2; exit 1; }
if devex_file_contains_any "$TEST_ROOT/wait-screen.txt" \
    'Viewing Review || Prove is locked'; then
  printf 'FAIL: alternate wait accepted an absent state\n' >&2
  exit 1
fi
devex_footer_is_navigate $'Esc prompt\nSCAN VIEW › NAVIGATE' \
  || { printf 'FAIL: Navigate footer was not recognized\n' >&2; exit 1; }
devex_footer_is_navigate $'last command\nlast notice\nNAVIGATION MODE — view keys active · Esc returns to prompt' \
  || { printf 'FAIL: generic Navigate footer was not recognized\n' >&2; exit 1; }
if devex_footer_is_navigate $'Esc prompt\nERROR · Review is locked  Esc dismiss'; then
  printf 'FAIL: dismissible error was mistaken for Navigate readiness\n' >&2
  exit 1
fi

for prompt in 'kz> report' 'kuzushi> report' 'MAP VIEW › report' 'kz> report  export'; do
  devex_prompt_contains_draft "$prompt" report \
    || { printf 'FAIL: intact draft was not recognized: %s\n' "$prompt" >&2; exit 1; }
done
for prompt in 'kz> reports' 'kz> re' 'kz> report export' 'NAVIGATION MODE'; do
  if devex_prompt_contains_draft "$prompt" report; then
    printf 'FAIL: absent or changed draft was accepted: %s\n' "$prompt" >&2
    exit 1
  fi
done

TARGET_FIXTURE="$TEST_ROOT/target"
mkdir -p "$TARGET_FIXTURE"
git -C "$TARGET_FIXTURE" init -q
printf 'fn main() {}\n' > "$TARGET_FIXTURE/main.rs"
git -C "$TARGET_FIXTURE" add main.rs
git -C "$TARGET_FIXTURE" -c user.name=devex -c user.email=devex@kuzushi commit -qm seed

# The source-tree receipt embeds one mode per entry, so a mode carrying the
# volatile filesystem counters GNU `stat -f` prints (`Blocks: ... Free: ...`)
# would forge TARGET DRIFT whenever any process writes to the same filesystem.
for mode_path in "$TARGET_FIXTURE/main.rs" "$TARGET_FIXTURE"; do
  path_mode=$(devex_path_mode "$mode_path")
  case $path_mode in
    ''|*[!0-7]*)
      printf 'FAIL: devex_path_mode returned a non-octal mode for %s: %s\n' \
        "$mode_path" "$path_mode" >&2
      exit 1
      ;;
  esac
  assert_eq 1 "$(printf '%s\n' "$path_mode" | wc -l | tr -d ' ')" \
    "devex_path_mode returns a single line for $mode_path"
done

devex_capture_target_source_status "$TARGET_FIXTURE" "$TEST_ROOT/status-before"
devex_capture_target_source_tree "$TARGET_FIXTURE" "$TEST_ROOT/tree-before"
mkdir -p "$TARGET_FIXTURE/.kuzushi"
printf 'normal product state\n' > "$TARGET_FIXTURE/.kuzushi/state"
devex_capture_target_source_status "$TARGET_FIXTURE" "$TEST_ROOT/status-kuzushi"
devex_capture_target_source_tree "$TARGET_FIXTURE" "$TEST_ROOT/tree-kuzushi"
assert_eq "$(devex_file_sha256 "$TEST_ROOT/status-before")" \
  "$(devex_file_sha256 "$TEST_ROOT/status-kuzushi")" \
  ".kuzushi changes are excluded from target source status"
assert_eq "$(devex_file_sha256 "$TEST_ROOT/tree-before")" \
  "$(devex_file_sha256 "$TEST_ROOT/tree-kuzushi")" \
  ".kuzushi changes are excluded from target source tree"

printf 'fn changed() {}\n' >> "$TARGET_FIXTURE/main.rs"
devex_capture_target_source_status "$TARGET_FIXTURE" "$TEST_ROOT/status-dirty-one"
devex_capture_target_source_tree "$TARGET_FIXTURE" "$TEST_ROOT/tree-dirty-one"
if [ "$(devex_file_sha256 "$TEST_ROOT/status-before")" = \
     "$(devex_file_sha256 "$TEST_ROOT/status-dirty-one")" ]; then
  printf 'FAIL: source change did not alter target source-status digest\n' >&2
  exit 1
fi

printf 'fn changed_again() {}\n' >> "$TARGET_FIXTURE/main.rs"
devex_capture_target_source_status "$TARGET_FIXTURE" "$TEST_ROOT/status-dirty-two"
devex_capture_target_source_tree "$TARGET_FIXTURE" "$TEST_ROOT/tree-dirty-two"
assert_eq "$(devex_file_sha256 "$TEST_ROOT/status-dirty-one")" \
  "$(devex_file_sha256 "$TEST_ROOT/status-dirty-two")" \
  "already-dirty tracked file keeps the same porcelain state"
if [ "$(devex_file_sha256 "$TEST_ROOT/tree-dirty-one")" = \
     "$(devex_file_sha256 "$TEST_ROOT/tree-dirty-two")" ]; then
  printf 'FAIL: source-tree digest missed changed bytes in already-dirty tracked file\n' >&2
  exit 1
fi
if devex_target_state_unchanged head \
    "$(devex_file_sha256 "$TEST_ROOT/status-dirty-one")" \
    "$(devex_file_sha256 "$TEST_ROOT/tree-dirty-one")" head \
    "$(devex_file_sha256 "$TEST_ROOT/status-dirty-two")" \
    "$(devex_file_sha256 "$TEST_ROOT/tree-dirty-two")"; then
  printf 'FAIL: drift comparison accepted changed bytes in already-dirty tracked file\n' >&2
  exit 1
fi

printf 'untracked one\n' > "$TARGET_FIXTURE/notes.txt"
devex_capture_target_source_status "$TARGET_FIXTURE" "$TEST_ROOT/status-untracked-one"
devex_capture_target_source_tree "$TARGET_FIXTURE" "$TEST_ROOT/tree-untracked-one"
printf 'untracked two\n' > "$TARGET_FIXTURE/notes.txt"
devex_capture_target_source_status "$TARGET_FIXTURE" "$TEST_ROOT/status-untracked-two"
devex_capture_target_source_tree "$TARGET_FIXTURE" "$TEST_ROOT/tree-untracked-two"
assert_eq "$(devex_file_sha256 "$TEST_ROOT/status-untracked-one")" \
  "$(devex_file_sha256 "$TEST_ROOT/status-untracked-two")" \
  "untracked file keeps the same porcelain state when only bytes change"
if [ "$(devex_file_sha256 "$TEST_ROOT/tree-untracked-one")" = \
     "$(devex_file_sha256 "$TEST_ROOT/tree-untracked-two")" ]; then
  printf 'FAIL: source-tree digest missed changed bytes in untracked file\n' >&2
  exit 1
fi

printf 'outside one\n' > "$TEST_ROOT/outside.txt"
ln -s "$TEST_ROOT/outside.txt" "$TARGET_FIXTURE/outside-link"
devex_capture_target_source_tree "$TARGET_FIXTURE" "$TEST_ROOT/tree-link-one"
printf 'outside two\n' > "$TEST_ROOT/outside.txt"
devex_capture_target_source_tree "$TARGET_FIXTURE" "$TEST_ROOT/tree-link-two"
assert_eq "$(devex_file_sha256 "$TEST_ROOT/tree-link-one")" \
  "$(devex_file_sha256 "$TEST_ROOT/tree-link-two")" \
  "source-tree digest hashes symlink identity without following outside target"

mkdir -p "$TEST_ROOT/bin"
printf '#!/bin/sh\nexit 0\n' > "$TEST_ROOT/bin/kz"
printf '#!/bin/sh\nexit 0\n' > "$TEST_ROOT/bin/kuzushi"
chmod +x "$TEST_ROOT/bin/kz" "$TEST_ROOT/bin/kuzushi"
devex_is_kz_wrapper_flow "$TEST_ROOT/bin/kz" "$TEST_ROOT/bin/kuzushi" \
  || { printf 'FAIL: distinct kz wrapper/native pair rejected\n' >&2; exit 1; }
if devex_is_kz_wrapper_flow "$TEST_ROOT/bin/kuzushi" "$TEST_ROOT/bin/kuzushi"; then
  printf 'FAIL: direct native binary masqueraded as kz wrapper\n' >&2
  exit 1
fi

test_tmux_session_keeps_exact_operator_binary_identity() (
  command -v tmux >/dev/null 2>&1 \
    || { printf 'FAIL: tmux is required for session environment contracts\n' >&2; exit 1; }
  unset TMUX KUZUSHI_NATIVE_BIN KUZUSHI_BIN KUZUSHI_DEVEX_TARGET
  tmux_socket="/tmp/kuzushi-devex-contract-$$"
  tmux() { command tmux -S "$tmux_socket" "$@"; }
  trap 'tmux kill-server 2>/dev/null || true' EXIT INT TERM

  # Start the isolated server first, without any audit identity in its global
  # environment. This reproduces a normal long-lived operator tmux server.
  tmux new-session -d -s devex-existing -x 40 -y 10 /bin/sh
  if tmux show-environment -g KUZUSHI_NATIVE_BIN >/dev/null 2>&1; then
    printf 'FAIL: isolated pre-existing tmux server unexpectedly has KUZUSHI_NATIVE_BIN\n' >&2
    exit 1
  fi

  native_dir="$TEST_ROOT/native dir;literal"
  native="$native_dir/kuzushi"
  wrapper_dir="$TEST_ROOT/session wrapper;literal"
  wrapper="$wrapper_dir/kz"
  target="$TEST_ROOT/target dir;literal"
  pane_receipt="$TEST_ROOT/pane-environment.txt"
  delegation_receipt="$TEST_ROOT/native-delegation.txt"
  mkdir -p "$native_dir" "$wrapper_dir" "$target"
  # shellcheck disable=SC2016 # Generate a fixture that expands these variables when it runs.
  printf '#!/bin/sh\nprintf "%%s\\n" "$0" > "$DEVEX_DELEGATION_RECEIPT"\nprintf "%%s\\n" "$@" >> "$DEVEX_DELEGATION_RECEIPT"\n' > "$native"
  chmod +x "$native"
  ln -s "$SCRIPT_DIR/../../bin/kuzushi-rs.mjs" "$wrapper"

  session=devex-contract
  devex_session_start "$session" 80 24 "$TEST_ROOT" "$native" "$wrapper" "$target"
  devex_send_line "$session" \
    "printf '%s\\n' \"\$KUZUSHI_NATIVE_BIN\" \"\$KUZUSHI_BIN\" \"\$KUZUSHI_DEVEX_TARGET\" > $(devex_shell_quote "$pane_receipt")"
  wait_for_file "$pane_receipt"
  assert_eq "$native" "$(sed -n '1p' "$pane_receipt")" \
    "pane receives exact KUZUSHI_NATIVE_BIN"
  assert_eq "$wrapper" "$(sed -n '2p' "$pane_receipt")" \
    "pane receives exact KUZUSHI_BIN"
  assert_eq "$target" "$(sed -n '3p' "$pane_receipt")" \
    "pane receives exact KUZUSHI_DEVEX_TARGET"

  devex_send_line "$session" \
    "DEVEX_DELEGATION_RECEIPT=$(devex_shell_quote "$delegation_receipt") \"\$KUZUSHI_BIN\" --delegation-probe"
  wait_for_file "$delegation_receipt"
  assert_eq "$native" "$(sed -n '1p' "$delegation_receipt")" \
    "kz wrapper delegates to exact session-native override"
  assert_eq "--delegation-probe" "$(sed -n '2p' "$delegation_receipt")" \
    "kz wrapper preserves delegated arguments"

  if tmux show-environment -g KUZUSHI_NATIVE_BIN >/dev/null 2>&1; then
    printf 'FAIL: session setup mutated tmux global KUZUSHI_NATIVE_BIN\n' >&2
    exit 1
  fi
  devex_session_kill "$session"
)

wait_for_file() { # <path>
  local attempt=0
  while [ "$attempt" -lt 40 ]; do
    [ -s "$1" ] && return 0
    attempt=$((attempt + 1))
    sleep 0.05
  done
  printf 'FAIL: timed out waiting for %s\n' "$1" >&2
  return 1
}

test_tmux_session_keeps_exact_operator_binary_identity

bash "$SCRIPT_DIR/test-required-snap.sh"

printf 'PASS: DevEx harness contracts\n'
