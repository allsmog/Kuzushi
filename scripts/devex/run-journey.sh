#!/usr/bin/env bash
# run-journey.sh — tmux-driven DevEx audit harness for the Kuzushi TUI.
#
# Drives the Rust Ratatui shell through scripted keystroke journeys
# (docs/devex/tui-devex-audit-journeys.md, J1–J16) plus the canonical five-phase
# reference (J17), and captures per-step tmux panes for
# signifier↔state↔intent review.
#
# Usage:
#   ./scripts/devex/run-journey.sh J1            # one journey
#   ./scripts/devex/run-journey.sh J1 J8 J4      # several
#   ./scripts/devex/run-journey.sh all           # J1..J17
#   ./scripts/devex/run-journey.sh --list        # catalog
#   ./scripts/devex/run-journey.sh --size 60x20 J1   # size override (J14 matrix)
#   ./scripts/devex/run-journey.sh --artifact-root /tmp/kuzushi-audit J17
#   ./scripts/devex/run-journey.sh --retain-successful 20 J17
#   ./scripts/devex/run-journey.sh --retain-all J17
#   KUZUSHI_BIN=... KUZUSHI_DEVEX_TARGET=... override binary / @TARGET token.
#   KUZUSHI_DEVEX_ARTIFACT_ROOT=... overrides the default artifact directory.
#   KUZUSHI_DEVEX_RETAIN_SUCCESSFUL=... overrides successful-run retention.
#
# Verdicts are honest: `expect:` lines are machine-checked substrings
# (PASS/FAIL); `ask:` lines are human-judgment invariant questions emitted as
# REVIEW items next to their snapshot — never faked into a pass. Exit 4 means
# machine checks passed but human judgment is still required.
set -eo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
JOURNEY_DIR="$SCRIPT_DIR/journeys"
DEFAULT_ARTIFACT_ROOT="$SCRIPT_DIR/artifacts"
DEFAULT_SIZE="110x32"
DEFAULT_WAIT_FOR_TIMEOUT=20
DEFAULT_RETAIN_SUCCESSFUL=20
DEVEX_RUSTUP_HOME=${RUSTUP_HOME:-${HOME:?}/.rustup}

# shellcheck source=scripts/devex/lib.sh
. "$SCRIPT_DIR/lib.sh"

usage() {
  sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# journey catalog
# ---------------------------------------------------------------------------
journey_file_for() { # J7 / j7 / J07 -> path
  local id n
  id=$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')
  n=${id#J}; n=${n#0}
  set -- "$JOURNEY_DIR/J$n-"*.journey
  [ -f "$1" ] || devex_die "no journey file matches J$n under $JOURNEY_DIR"
  printf '%s' "$1"
}

journey_name_of() {
  sed -n 's/^name:[[:space:]]*//p' "$1" | head -1
}

list_journeys() {
  local f
  for f in "$JOURNEY_DIR"/J*.journey; do
    printf '  %-42s %s\n' "$(basename "$f" .journey)" "$(journey_name_of "$f")"
  done
}

# ---------------------------------------------------------------------------
# per-journey state (reset in run_journey)
# ---------------------------------------------------------------------------
SESSION="" JDIR="" REPORT="" LAST_SNAP="" LAST_ANSI="" LAST_SNAP_NAME="(no snapshot yet)"
SNAP_IDX=0 PASS_N=0 FAIL_N=0 REVIEW_N=0
J_COLS=0 J_ROWS=0 J_CWD="" SESSION_STARTED=0
ENV_PREFIX=""    # accumulated `env -u K K=V` prefix, consumed by next launch
TMP_HOME="" FIXTURE_TARGET=""
ACTIVE_PROFILE="default" ACTIVE_LAUNCH_ARGS="" ACTIVE_TARGET_CONTEXT="not launched"
# 1 once an interactive `launch:` has started the TUI, which owns the terminal
# in raw mode. `launch-raw:` journeys may be headless and keep this at 0.
ACTIVE_LAUNCH_OWNS_TERMINAL=0
TARGET_PROOF_REQUIRED=0 TARGET_PROOF_ACTIVE=0 TARGET_REAL="" TARGET_TOPLEVEL=""
TARGET_HEAD_BEFORE="" TARGET_STATUS_BEFORE="" TARGET_TREE_BEFORE=""

report() { # <TAG> <text>
  printf '  [%s] %s\n' "$1" "$2" | tee -a "$REPORT"
}

pass()   { PASS_N=$((PASS_N + 1));     report PASS   "$1"; }
fail()   { FAIL_N=$((FAIL_N + 1));     report FAIL   "$1"; }
review() { REVIEW_N=$((REVIEW_N + 1)); report REVIEW "$1"; }

# ---------------------------------------------------------------------------
# tokens available to journey files
# ---------------------------------------------------------------------------
ensure_tmp_home() {
  TMP_HOME="$JDIR/home"
  mkdir -p "$TMP_HOME"
}

ensure_fixture_target() {
  FIXTURE_TARGET="$JDIR/fixture-target"
  [ -d "$FIXTURE_TARGET" ] && return 0
  mkdir -p "$FIXTURE_TARGET"
  git -C "$FIXTURE_TARGET" init -q 2>/dev/null || true
  printf 'import os\n\ndef run(cmd):\n    os.system(cmd)  # command injection fixture\n' \
    > "$FIXTURE_TARGET/app.py"
  printf '# fixture credentials (AWS documentation example key — not real)\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n' \
    > "$FIXTURE_TARGET/config.env"
}

expand_tokens() {
  local s=$1
  s=${s//@KUZUSHI/$KUZUSHI_BIN}
  s=${s//@REPO/$REPO_ROOT}
  s=${s//@ART/$JDIR}
  case $s in *@TMP_HOME*)   ensure_tmp_home;       s=${s//@TMP_HOME/$TMP_HOME};; esac
  case $s in *@TMP_TARGET*) ensure_fixture_target; s=${s//@TMP_TARGET/$FIXTURE_TARGET};; esac
  case $s in *@TARGET*)
    if [ -n "$KUZUSHI_DEVEX_TARGET" ]; then s=${s//@TARGET/$KUZUSHI_DEVEX_TARGET}
    else ensure_fixture_target; s=${s//@TARGET/$FIXTURE_TARGET}; fi;;
  esac
  printf '%s' "$s"
}

profile_for_launch_env() {
  case $1 in
    *NO_COLOR=*) printf '%s' no-color;;
    *KUZUSHI_THEME=high-contrast*) printf '%s' high-contrast;;
    *COLORTERM=truecolor*) printf '%s' truecolor;;
    *TERM=xterm-256color*) printf '%s' ansi256;;
    *) printf '%s' default;;
  esac
}

write_target_state_receipt() { # <label> <head> <status-digest> <status-file> <tree-digest> <tree-file>
  local label=$1 head=$2 status_digest=$3 status_file=$4 tree_digest=$5 tree_file=$6 timestamp
  timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  {
    printf '{\n'
    printf '  "label": "%s",\n' "$(json_escape "$label")"
    printf '  "timestamp_utc": "%s",\n' "$(json_escape "$timestamp")"
    printf '  "target_requested": "%s",\n' "$(json_escape "$KUZUSHI_DEVEX_TARGET")"
    printf '  "target_canonical": "%s",\n' "$(json_escape "$TARGET_REAL")"
    printf '  "target_toplevel": "%s",\n' "$(json_escape "$TARGET_TOPLEVEL")"
    printf '  "target_head": "%s",\n' "$(json_escape "$head")"
    printf '  "source_status_sha256": "%s",\n' "$(json_escape "$status_digest")"
    printf '  "source_status_excludes": ".kuzushi",\n'
    printf '  "source_status_receipt": "%s",\n' "$(json_escape "$(devex_canonical_path "$status_file")")"
    printf '  "source_tree_sha256": "%s",\n' "$(json_escape "$tree_digest")"
    printf '  "source_tree_scope": "tracked and non-ignored untracked worktree entries",\n'
    printf '  "source_tree_excludes": ".git,.kuzushi",\n'
    printf '  "source_tree_receipt": "%s"\n' "$(json_escape "$(devex_canonical_path "$tree_file")")"
    printf '}\n'
  } > "$JDIR/target-$label.provenance.json"
}

capture_target_state() { # <before|after>
  local label=$1 status_file tree_file head status_digest tree_digest
  status_file="$JDIR/target-$label.source-status.txt"
  tree_file="$JDIR/target-$label.source-tree.txt"
  if ! devex_capture_target_source_status "$TARGET_REAL" "$status_file"; then
    fail "target $label source status could not be captured from $TARGET_REAL"
    return 1
  fi
  head=$(git -C "$TARGET_REAL" rev-parse HEAD 2>/dev/null) || {
    fail "target $label HEAD could not be resolved from $TARGET_REAL"
    return 1
  }
  if ! devex_capture_target_source_tree "$TARGET_REAL" "$tree_file"; then
    fail "target $label source tree could not be captured from $TARGET_REAL"
    return 1
  fi
  status_digest=$(devex_file_sha256 "$status_file")
  tree_digest=$(devex_file_sha256 "$tree_file")
  [ "$status_digest" != unavailable ] && [ "$tree_digest" != unavailable ] || {
    fail "target $label source state cannot be authenticated: no SHA-256 tool"
    return 1
  }
  if ! write_target_state_receipt "$label" "$head" "$status_digest" "$status_file" \
      "$tree_digest" "$tree_file"; then
    fail "target $label provenance receipt could not be written"
    return 1
  fi
  case $label in
    before)
      TARGET_HEAD_BEFORE=$head
      TARGET_STATUS_BEFORE=$status_digest
      TARGET_TREE_BEFORE=$tree_digest
      ;;
    after)
      TARGET_HEAD_AFTER=$head
      TARGET_STATUS_AFTER=$status_digest
      TARGET_TREE_AFTER=$tree_digest
      ;;
  esac
  report target "$label · $TARGET_REAL @ $head · status sha256:$status_digest · tree sha256:$tree_digest (.git/.kuzushi excluded)"
}

ensure_target_proof() {
  [ "$TARGET_PROOF_REQUIRED" = 1 ] || return 0
  [ "$TARGET_PROOF_ACTIVE" = 0 ] || return 0
  [ -n "$KUZUSHI_DEVEX_TARGET" ] || {
    fail "real-target journey requires KUZUSHI_DEVEX_TARGET"
    return 1
  }
  [ -d "$KUZUSHI_DEVEX_TARGET" ] || {
    fail "real-target journey target is not a directory: $KUZUSHI_DEVEX_TARGET"
    return 1
  }
  TARGET_REAL=$(devex_canonical_path "$KUZUSHI_DEVEX_TARGET") || {
    fail "real-target journey target cannot be canonicalized: $KUZUSHI_DEVEX_TARGET"
    return 1
  }
  TARGET_TOPLEVEL=$(git -C "$TARGET_REAL" rev-parse --show-toplevel 2>/dev/null) || {
    fail "real-target journey target is not a Git worktree: $TARGET_REAL"
    return 1
  }
  TARGET_TOPLEVEL=$(devex_canonical_path "$TARGET_TOPLEVEL")
  capture_target_state before || return 1
  TARGET_PROOF_ACTIVE=1
}

finish_target_proof() {
  [ "$TARGET_PROOF_ACTIVE" = 1 ] || return 0
  capture_target_state after || return 1
  if ! devex_target_state_unchanged \
      "$TARGET_HEAD_BEFORE" "$TARGET_STATUS_BEFORE" "$TARGET_TREE_BEFORE" \
      "$TARGET_HEAD_AFTER" "$TARGET_STATUS_AFTER" "$TARGET_TREE_AFTER"; then
    fail "TARGET DRIFT · before $TARGET_HEAD_BEFORE/$TARGET_STATUS_BEFORE/$TARGET_TREE_BEFORE · after $TARGET_HEAD_AFTER/$TARGET_STATUS_AFTER/$TARGET_TREE_AFTER"
    return 1
  fi
  pass "target HEAD, source status, and source tree unchanged (.git/.kuzushi excluded)"
}

# ---------------------------------------------------------------------------
# directives
# ---------------------------------------------------------------------------
ensure_session() {
  [ "$SESSION_STARTED" = 1 ] && return 0
  devex_session_start \
    "$SESSION" "$J_COLS" "$J_ROWS" "$J_CWD" \
    "${KUZUSHI_NATIVE_BIN:-}" "$KUZUSHI_BIN" "$KUZUSHI_DEVEX_TARGET"
  SESSION_STARTED=1
  sleep 0.5
}

d_size() { # COLSxROWS (ignored when --size override is set)
  [ "$SESSION_STARTED" = 1 ] && devex_die "size: must precede the first launch/keys/snap"
  [ -n "$SIZE_OVERRIDE" ] && return 0
  J_COLS=${1%x*}; J_ROWS=${1#*x}
}

d_resize() { # Resize a running journey; subsequent captures record the new size.
  ensure_session
  [[ "$1" =~ ^[1-9][0-9]*x[1-9][0-9]*$ ]] || devex_die "resize: expected positive COLSxROWS"
  local cols=${1%x*} rows=${1#*x}
  tmux resize-window -t "$SESSION" -x "$cols" -y "$rows"
  J_COLS=$cols
  J_ROWS=$rows
  report step "resize: $1"
}

d_cwd() {
  local dir; dir=$(expand_tokens "$1")
  mkdir -p "$dir"
  if [ "$SESSION_STARTED" = 1 ]; then
    devex_send_line "$SESSION" "cd $(devex_shell_quote "$dir")"
  else
    J_CWD=$dir
  fi
}

d_env() { # K=V [K=V...]
  local kv
  for kv in $1; do
    ENV_PREFIX="$ENV_PREFIX$(devex_shell_quote "$(expand_tokens "$kv")") "
  done
}

d_env_unset() { # K [K...]
  local k
  # `env` requires option flags before NAME=VALUE assignments on macOS.
  # Prepending keeps `env-unset:` valid regardless of directive order.
  for k in $1; do ENV_PREFIX="-u $k $ENV_PREFIX"; done
}

d_require_env() { # all named vars must be set, else skip journey
  local k
  for k in $1; do
    if [ -z "$(eval "printf '%s' \"\${$k}\"")" ]; then
      report SKIP "requires \$$k — not set in this environment"
      return 3
    fi
  done
}

d_require_any_env() { # at least one named var must be set
  local k
  for k in $1; do
    [ -n "$(eval "printf '%s' \"\${$k}\"")" ] && return 0
  done
  report SKIP "requires one of: $1 — none set in this environment"
  return 3
}

d_require_wrapper_flow() {
  local wrapper_hash native_hash
  if [ -z "${KUZUSHI_NATIVE_BIN:-}" ]; then
    report step "wrapper-flow proof not requested (KUZUSHI_NATIVE_BIN is unset)"
    return 0
  fi
  if devex_is_kz_wrapper_flow "$KUZUSHI_BIN" "$KUZUSHI_NATIVE_BIN"; then
    wrapper_hash=$(devex_file_sha256 "$KUZUSHI_BIN")
    native_hash=$(devex_file_sha256 "$KUZUSHI_NATIVE_BIN")
    if [ "$wrapper_hash" = unavailable ] || [ "$native_hash" = unavailable ]; then
      fail "wrapper-flow identities cannot be authenticated: no SHA-256 tool"
      return 1
    fi
    pass "operator journey uses kz wrapper with explicit KUZUSHI_NATIVE_BIN"
    return 0
  fi
  fail "wrapper-flow required: KUZUSHI_BIN must be an executable kz wrapper distinct from executable KUZUSHI_NATIVE_BIN"
  return 1
}

d_shell() { # host-side setup command (fixture seeding etc.)
  local cmd; cmd=$(expand_tokens "$1")
  sh -c "$cmd" || fail "shell setup failed: $cmd"
}

launch_cmd() { # assemble `env -u K K=V ... <cmd>`
  local tail=$1 prefix=""
  if [ -n "$ENV_PREFIX" ]; then
    prefix="env ${ENV_PREFIX}RUSTUP_HOME=$(devex_shell_quote "$DEVEX_RUSTUP_HOME") "
  else
    prefix="env RUSTUP_HOME=$(devex_shell_quote "$DEVEX_RUSTUP_HOME") "
  fi
  printf '%s' "$prefix$tail"
}

d_launch() { # args appended to the kuzushi binary ('' = bare launch)
  ensure_target_proof || return $?
  ensure_session
  local args cmd; args=$(expand_tokens "$1")
  ACTIVE_PROFILE=$(profile_for_launch_env "$ENV_PREFIX")
  ACTIVE_LAUNCH_ARGS=$args
  ACTIVE_LAUNCH_OWNS_TERMINAL=1
  case " $args " in
    *' --target '*) ACTIVE_TARGET_CONTEXT=$args;;
    *) ACTIVE_TARGET_CONTEXT="interactive target selection from $J_CWD";;
  esac
  cmd=$(launch_cmd "$(devex_shell_quote "$KUZUSHI_BIN")${args:+ $args}")
  ENV_PREFIX=""
  devex_send_line "$SESSION" "$cmd"
  report step "launch: $(basename "$KUZUSHI_BIN")${args:+ $args}"
}

d_launch_raw() { # full shell command line (pipes, --plain, non-TTY checks)
  ensure_target_proof || return $?
  ensure_session
  local raw cmd; raw=$(expand_tokens "$1")
  ACTIVE_PROFILE=$(profile_for_launch_env "$ENV_PREFIX")
  ACTIVE_LAUNCH_ARGS=$raw
  ACTIVE_LAUNCH_OWNS_TERMINAL=0
  ACTIVE_TARGET_CONTEXT="command-defined or headless"
  cmd=$(launch_cmd "$raw")
  ENV_PREFIX=""
  devex_send_line "$SESSION" "$cmd"
  report step "launch-raw: $raw"
}

d_keys() { # raw tmux send-keys tokens: Enter Escape C-c C-Up j k ...
  ensure_session
  # shellcheck disable=SC2086
  tmux send-keys -t "$SESSION" $1
  report step "keys: $1"
}

d_type() { # literal text, no Enter
  ensure_session
  tmux send-keys -t "$SESSION" -l -- "$(expand_tokens "$1")"
  report step "type: $1"
}

d_paste_file() { # bounded literal bracketed paste, no Enter
  ensure_session
  local path bytes buffer
  path=$(expand_tokens "$1")
  [ -f "$path" ] || { fail "paste-file requires a regular file: $path"; return 1; }
  bytes=$(wc -c < "$path")
  [ "$bytes" -le 65536 ] || { fail "paste-file exceeds 64 KiB: $path"; return 1; }
  buffer="${SESSION}-paste"
  tmux load-buffer -b "$buffer" "$path"
  tmux paste-buffer -d -p -b "$buffer" -t "$SESSION"
  report step "paste-file: $path ($bytes bytes)"
}

d_submit() { # literal text + Enter (the common "type a verb" case)
  ensure_session
  # Normalize the shell to a clean Prompt before typing. Esc is a toggle
  # (clean prompt <-> Navigate) and a clearer (drafted prompt -> clean), so no
  # blind key sequence can converge; poll the mode markers the shell renders:
  # the Navigate footer advertises "Esc prompt", the Prompt footer advertises
  # "Esc nav mode", and a CLEAN prompt shows its placeholder ("· Esc list
  # keys" on workbench pages, "type help or press Tab" elsewhere). F2 must
  # never be sent — it is no longer a mode toggle, and delivered raw its
  # ESC O Q bytes type a literal "OQ" into the prompt.
  local tries=0 tail3
  while (( tries++ < 10 )); do
    tail3=$(tmux capture-pane -t "$SESSION" -p 2>/dev/null | tail -3)
    case $tail3 in
      *'Esc list keys'* | *'type help or press Tab'*)
        break;;                               # clean prompt — ready for input
      *'command prompt paused'*)
        # Picker-style views park the prompt entirely; the advertised ":"
        # reopens it (Escape only cycles picker states and never converges).
        tmux send-keys -t "$SESSION" :;;
      *)
        # Navigate -> Prompt, drafted prompt -> cleared, or notice/completion
        # card -> dismissed; re-check the rendered state before each press.
        tmux send-keys -t "$SESSION" Escape;;
    esac
    sleep 0.3
  done
  # The TUI event loop can lag seconds behind send-keys while async target
  # hydration runs, and hydration events can wipe or corrupt an in-flight
  # draft — typing blind then pressing Enter submits garbage (observed: the
  # command "scan" arriving as "scanj" in the session transcript). Type, wait
  # until the draft renders intact at the end of the prompt line, and only
  # then commit with Enter; a corrupted draft is cleared and retyped.
  local text attempt=0 waited line
  text=$(expand_tokens "$1")
  while (( attempt++ <= 4 )); do
    tmux send-keys -t "$SESSION" -l -- "$text"
    waited=0
    while (( waited++ <= 40 )); do
      line=$(tmux capture-pane -t "$SESSION" -p 2>/dev/null | tail -1)
      line=${line%"${line##*[![:space:]]}"}   # strip trailing blanks/cursor
      # A clean draft ends the line, or is followed by a two-space-separated
      # inline completion ghost (e.g. "› findings  export"). A one-character
      # corruption ("› scanj") matches neither form.
      if devex_prompt_contains_draft "$line" "$text"; then
          tmux send-keys -t "$SESSION" Enter
          report step "submit: $1"
          return 0
      fi
      sleep 0.25
    done
    tmux send-keys -t "$SESSION" Escape       # clear the corrupted draft
    sleep 0.5
  done
  fail "submit: $1 — draft never rendered intact on the prompt line"
}

d_nav_mode() { # converge the shell to Navigate mode (page keys / view hotkeys)
  ensure_session
  # Same footer-marker polling as d_submit, aimed at the opposite mode: a
  # Navigate footer advertises "Esc prompt"; from a clean prompt one Escape
  # enters Navigate, and a drafted prompt or modal needs a clearing Escape
  # first. Blind Escapes cannot converge on a toggle — poll between presses.
  # The window must cover launch-time hydration: on a large real target the
  # footer does not render its mode segment for several seconds (observed
  # >3s on a 442k-file monorepo), so give convergence the same order of
  # patience as the page waits (30s) while still failing honestly.
  # A key sent just before (e.g. `keys: Escape`) may not have rendered yet,
  # so one read of a stale Navigate footer is not convergence: the footer
  # must hold across two identical footer captures 0.5s apart. Otherwise the next
  # page digit lands in Prompt mode and is typed (seen on a loaded host).
  local tries=0 frame settled
  while (( tries++ <= 60 )); do
    frame=$(tmux capture-pane -t "$SESSION" -p 2>/dev/null | tail -3)
    sleep 0.5
    settled=$(tmux capture-pane -t "$SESSION" -p 2>/dev/null | tail -3)
    if [ "$frame" = "$settled" ] && devex_footer_is_navigate "$settled"; then
      report step "nav-mode (converged)"
      return 0
    fi
    [ "$frame" = "$settled" ] && tmux send-keys -t "$SESSION" Escape
  done
  fail "nav-mode — Navigate footer never rendered"
}

# Dispose of a completed phase-result card by its own advertised key.
# Those keys (app/phase_results.rs) are Navigate-mode only; Prompt mode types
# them. Converge on Navigate, press, and re-check the status footer's "result
# ready" chip — the same poll-press-recheck shape d_submit and d_nav_mode use.
# A re-press read from a lagging frame is safe: Navigate absorbs a repeat of
# the key that just resolved the card, and a card key off the Workbench only
# reveals the card (state_transitions/phase_result_navigate.rs), so neither
# can leak into the composer. A footer reading "Esc dismiss notice" is not
# Navigate-ready; the Escape sent below dismisses that notice first.
d_phase_result() { # <card key, e.g. n>
  ensure_session
  local key=$1 tries=0 tail3
  while (( tries++ <= 24 )); do
    if ! devex_pane_contains "$SESSION" "result ready"; then
      report step "phase-result: $key (card resolved)"
      return 0
    fi
    tail3=$(tmux capture-pane -t "$SESSION" -p 2>/dev/null | tail -3)
    if devex_footer_is_navigate "$tail3"; then
      tmux send-keys -t "$SESSION" "$key"
    else
      tmux send-keys -t "$SESSION" Escape
    fi
    sleep 0.5
  done
  fail "phase-result: $key — the result card never resolved"
}

d_wait() { sleep "$1"; }

# After an interactive `launch:`, a needle only counts once the TUI owns the
# terminal. Matching the pre-TUI boot banner in the scrollback would release
# the following `keys:` into a still-cooked tty — see devex_live_pane_contains.
wait_for_needle_visible() { # <session> <needle>
  if [ "$ACTIVE_LAUNCH_OWNS_TERMINAL" = 1 ]; then
    devex_live_pane_contains "$1" "$2"
  else
    devex_pane_contains "$1" "$2"
  fi
}

d_wait_for() { # [timeout-secs] <substring>  — poll the pane, bounded, honest
  ensure_session
  local timeout=$DEFAULT_WAIT_FOR_TIMEOUT needle=$1 waited=0
  case $needle in
    [0-9]*' '*) timeout=${needle%% *}; needle=${needle#* };;
  esac
  needle=$(expand_tokens "$needle")
  # Include the exact timeout boundary: a two-second SLO gets checks at
  # 0.0, 0.5, 1.0, 1.5, and 2.0 seconds rather than failing at 1.5.
  while [ "$waited" -le "$((timeout * 2))" ]; do
    if wait_for_needle_visible "$SESSION" "$needle"; then
      pass "wait-for \"$needle\" (within ${timeout}s)"
      return 0
    fi
    sleep 0.5; waited=$((waited + 1))
  done
  fail "wait-for \"$needle\" timed out after ${timeout}s"
}

prepare_snapshot() { # <label>
  SNAP_IDX=$((SNAP_IDX + 1))
  local label
  label=$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '-')
  PENDING_SNAP_NAME=$(printf '%02d-%s' "$SNAP_IDX" "$label")
  PENDING_SNAP="$JDIR/$PENDING_SNAP_NAME.txt"
  PENDING_ANSI="$JDIR/$PENDING_SNAP_NAME.ansi"
  PENDING_META="$JDIR/$PENDING_SNAP_NAME.provenance.json"
}

canonical_file_path() {
  devex_canonical_path "$1" || printf '%s' "$1"
}

file_sha256() {
  devex_file_sha256 "$1"
}

file_mtime_epoch() {
  stat -f '%m' "$1" 2>/dev/null || stat -c '%Y' "$1" 2>/dev/null || printf '%s' unavailable
}

write_snapshot_provenance() { # <capture-kind>
  local kind=$1 actual alt binary_path binary_version binary_hash binary_mtime
  local native_requested native_path native_hash native_mtime
  local head dirty_count dirty timestamp tmux_version journey rendered_target
  actual=$(tmux display-message -p -t "$SESSION" '#{pane_width} #{pane_height}')
  # shellcheck disable=SC2086 # Split the trusted two-field tmux format.
  set -- $actual
  alt=$(tmux display-message -p -t "$SESSION" '#{alternate_on}')
  binary_path=$(canonical_file_path "$KUZUSHI_BIN")
  binary_version=$("$KUZUSHI_BIN" --version 2>/dev/null | head -1 || printf '%s' unavailable)
  binary_hash=$(file_sha256 "$KUZUSHI_BIN")
  binary_mtime=$(file_mtime_epoch "$KUZUSHI_BIN")
  native_requested=${KUZUSHI_NATIVE_BIN:-}
  if [ -n "$native_requested" ] && [ -f "$native_requested" ]; then
    native_path=$(canonical_file_path "$native_requested")
    native_hash=$(file_sha256 "$native_requested")
    native_mtime=$(file_mtime_epoch "$native_requested")
  else
    native_path=unavailable
    native_hash=unavailable
    native_mtime=unavailable
  fi
  head=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || printf '%s' unavailable)
  dirty_count=$(git -C "$REPO_ROOT" status --porcelain --untracked-files=normal 2>/dev/null | awk 'END { print NR + 0 }')
  [ "$dirty_count" -gt 0 ] && dirty=true || dirty=false
  timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  tmux_version=$(tmux -V 2>/dev/null || printf '%s' unavailable)
  journey=$(basename "$CURRENT_FILE")
  rendered_target=$(grep -m 1 -E 'target[[:space:]:]' "$PENDING_SNAP" 2>/dev/null || printf '%s' unavailable)
  {
    printf '{\n'
    printf '  "capture_kind": "%s",\n' "$(json_escape "$kind")"
    printf '  "timestamp_utc": "%s",\n' "$(json_escape "$timestamp")"
    printf '  "journey": "%s",\n' "$(json_escape "$journey")"
    printf '  "step": %s,\n' "$SNAP_IDX"
    printf '  "label": "%s",\n' "$(json_escape "$PENDING_SNAP_NAME")"
    printf '  "binary_path": "%s",\n' "$(json_escape "$binary_path")"
    printf '  "binary_version": "%s",\n' "$(json_escape "$binary_version")"
    printf '  "binary_sha256": "%s",\n' "$(json_escape "$binary_hash")"
    printf '  "binary_mtime_epoch": "%s",\n' "$(json_escape "$binary_mtime")"
    printf '  "wrapper_invocation": "%s",\n' "$(json_escape "$KUZUSHI_BIN")"
    printf '  "wrapper_resolved_path": "%s",\n' "$(json_escape "$binary_path")"
    printf '  "wrapper_sha256": "%s",\n' "$(json_escape "$binary_hash")"
    printf '  "native_override": "%s",\n' "$(json_escape "${native_requested:-unset}")"
    printf '  "native_resolved_path": "%s",\n' "$(json_escape "$native_path")"
    printf '  "native_sha256": "%s",\n' "$(json_escape "$native_hash")"
    printf '  "native_mtime_epoch": "%s",\n' "$(json_escape "$native_mtime")"
    printf '  "head": "%s",\n' "$(json_escape "$head")"
    printf '  "kuzushi_head": "%s",\n' "$(json_escape "$head")"
    printf '  "dirty": %s,\n' "$dirty"
    printf '  "dirty_entry_count": %s,\n' "$dirty_count"
    printf '  "target_context": "%s",\n' "$(json_escape "$ACTIVE_TARGET_CONTEXT")"
    printf '  "target_canonical": "%s",\n' "$(json_escape "${TARGET_REAL:-unavailable}")"
    printf '  "target_head_at_start": "%s",\n' "$(json_escape "${TARGET_HEAD_BEFORE:-unavailable}")"
    printf '  "target_source_status_sha256_at_start": "%s",\n' "$(json_escape "${TARGET_STATUS_BEFORE:-unavailable}")"
    printf '  "target_source_tree_sha256_at_start": "%s",\n' "$(json_escape "${TARGET_TREE_BEFORE:-unavailable}")"
    printf '  "rendered_target_line": "%s",\n' "$(json_escape "$rendered_target")"
    printf '  "launch_args": "%s",\n' "$(json_escape "$ACTIVE_LAUNCH_ARGS")"
    printf '  "terminal_profile": "%s",\n' "$(json_escape "$ACTIVE_PROFILE")"
    printf '  "requested_dimensions": {"width": %s, "height": %s},\n' "$J_COLS" "$J_ROWS"
    printf '  "actual_dimensions": {"width": %s, "height": %s},\n' "${1:-0}" "${2:-0}"
    printf '  "tmux_version": "%s",\n' "$(json_escape "$tmux_version")"
    printf '  "alternate_on": %s\n' "${alt:-0}"
    printf '}\n'
  } > "$PENDING_META"
}

publish_snapshot() { # <capture-kind>
  write_snapshot_provenance "$1"
  LAST_SNAP=$PENDING_SNAP
  LAST_ANSI=$PENDING_ANSI
  LAST_SNAP_NAME=$PENDING_SNAP_NAME
  report snap "$LAST_SNAP_NAME.txt (+ .ansi + .provenance.json; $1)"
}

discard_pending_snapshot() {
  rm -f "$PENDING_SNAP" "$PENDING_ANSI" "$PENDING_META"
  LAST_SNAP="" LAST_ANSI="" LAST_SNAP_NAME="(no snapshot yet)"
}

automatic_capture_kind() {
  if devex_alternate_active "$SESSION"; then
    printf '%s' automatic-live
  else
    printf '%s' automatic-saved-or-pane
  fi
}

capture_pending() { # <automatic|live|saved>
  case $1 in
    automatic) devex_capture "$SESSION" "$PENDING_SNAP" "$PENDING_ANSI";;
    live) devex_capture_live "$SESSION" "$PENDING_SNAP" "$PENDING_ANSI";;
    saved) devex_capture_saved "$SESSION" "$PENDING_SNAP" "$PENDING_ANSI";;
    *) return 2;;
  esac
}

d_wait_snap_kind() { # <automatic|live> <[timeout] substring[ || substring] | label>
  ensure_session
  local requested_kind=$1 timeout=$DEFAULT_WAIT_FOR_TIMEOUT spec=$2
  local needle label waited=0 recorded_kind
  case $spec in
    *' | '*) label=${spec##* | }; spec=${spec% | *};;
    *) devex_die "wait snapshot requires '[timeout] substring | label'";;
  esac
  case $spec in
    [0-9]*' '*) timeout=${spec%% *}; needle=${spec#* };;
    *) needle=$spec;;
  esac
  needle=$(expand_tokens "$needle")
  prepare_snapshot "$label"
  while [ "$waited" -le "$((timeout * 2))" ]; do
    if capture_pending "$requested_kind" \
        && devex_file_contains_any "$PENDING_SNAP" "$needle"; then
      [ "$requested_kind" = automatic ] \
        && recorded_kind=$(automatic_capture_kind) \
        || recorded_kind=$requested_kind
      pass "wait-$requested_kind-snap \"$needle\" (within ${timeout}s)"
      publish_snapshot "$recorded_kind"
      return 0
    fi
    sleep 0.5; waited=$((waited + 1))
  done
  # Timed out: keep one final capture as a .timeout diagnosis artifact so the
  # failing screen is evidenced, but never publish it as the last snapshot —
  # the following expects must still report "no snapshot yet" honestly.
  if capture_pending automatic; then
    mv "$PENDING_SNAP" "${PENDING_SNAP%.txt}.timeout.txt" 2>/dev/null || true
    mv "$PENDING_ANSI" "${PENDING_ANSI%.ansi}.timeout.ansi" 2>/dev/null || true
    report snap "$PENDING_SNAP_NAME.timeout.txt (diagnosis capture of the timed-out screen)"
  fi
  discard_pending_snapshot
  fail "wait-$requested_kind-snap \"$needle\" timed out after ${timeout}s"
}

d_wait_snap() { d_wait_snap_kind automatic "$1"; }
d_wait_live_snap() { d_wait_snap_kind live "$1"; }

d_require_live_snap() {
  local failures_before=$FAIL_N
  d_wait_live_snap "$1"
  [ "$FAIL_N" -eq "$failures_before" ]
}

d_snap_kind() { # <automatic|live|saved> <label>
  ensure_session
  local requested_kind=$1 label=$2 recorded_kind
  prepare_snapshot "$label"
  if ! capture_pending "$requested_kind"; then
    discard_pending_snapshot
    fail "$requested_kind-snap \"$label\" could not capture the requested screen"
    return
  fi
  [ "$requested_kind" = automatic ] \
    && recorded_kind=$(automatic_capture_kind) \
    || recorded_kind=$requested_kind
  publish_snapshot "$recorded_kind"
}

d_snap() { d_snap_kind automatic "$1"; }
d_live_snap() { d_snap_kind live "$1"; }
d_saved_snap() { d_snap_kind saved "$1"; }

d_expect_wide() { # <min-cols> <substring> — assert only at widths where the
  # full layout renders. NOT a silent skip: below the threshold the step is
  # reported visibly, and the omission it tolerates must be a ledgered
  # compact-layout gap, never an unexplained absence.
  local min=${1%% *} rest=${1#* }
  case $min in
    ''|*[!0-9]*) devex_die "expect-wide requires '<min-cols> <substring>' (in $CURRENT_FILE)";;
  esac
  if [ "$J_COLS" -ge "$min" ]; then
    d_expect "$rest"
  else
    report step "expect-wide skipped at ${J_COLS}col (< ${min}col): \"$rest\" — compact-layout gap, see gap ledger"
  fi
}

d_expect() { # fixed substring, case-insensitive, against last snapshot
  local needle; needle=$(expand_tokens "$1")
  [ -n "$LAST_SNAP" ] || { fail "expect \"$needle\" — no snapshot taken yet"; return; }
  if grep -Fiq -- "$needle" "$LAST_SNAP"; then
    pass "$LAST_SNAP_NAME contains \"$needle\""
  else
    fail "$LAST_SNAP_NAME missing \"$needle\""
  fi
}

d_expect_not() {
  local needle; needle=$(expand_tokens "$1")
  [ -n "$LAST_SNAP" ] || { fail "expect-not \"$needle\" — no snapshot taken yet"; return; }
  if grep -Fiq -- "$needle" "$LAST_SNAP"; then
    fail "$LAST_SNAP_NAME unexpectedly contains \"$needle\""
  else
    pass "$LAST_SNAP_NAME free of \"$needle\""
  fi
}

d_expect_ansi_profile() { # indexed | truecolor, against last ANSI snapshot
  local profile=$1
  [ -n "$LAST_ANSI" ] || {
    fail "expect-ansi-profile \"$profile\" — no snapshot taken yet"
    return
  }
  case $profile in
    indexed)
      if ! devex_ansi_has_profile "$LAST_ANSI" indexed; then
        fail "$LAST_SNAP_NAME has no indexed-color SGR (38;5 / 48;5)"
      elif devex_ansi_has_profile "$LAST_ANSI" truecolor; then
        fail "$LAST_SNAP_NAME leaks RGB SGR into the indexed-color cell"
      else
        pass "$LAST_SNAP_NAME uses indexed-color SGR without RGB SGR"
      fi
      ;;
    truecolor)
      if devex_ansi_has_profile "$LAST_ANSI" truecolor; then
        pass "$LAST_SNAP_NAME uses RGB SGR (38;2 / 48;2)"
      else
        fail "$LAST_SNAP_NAME has no RGB SGR (38;2 / 48;2)"
      fi
      ;;
    *) devex_die "unknown ANSI profile '$profile' (expected indexed or truecolor)";;
  esac
}

d_ask() { # human-judgment checkpoint — recorded, never auto-verdicted
  review "($LAST_SNAP_NAME) $1"
}

d_expect_echo_within() { # <budget-ms> <probe-text> — type probe, time until echoed
  ensure_session
  local budget=${1%% *} probe=${1#* } start now elapsed_ms
  probe=$(expand_tokens "$probe")
  start=$(date +%s%N)
  tmux send-keys -t "$SESSION" -l -- "$probe"
  while :; do
    now=$(date +%s%N)
    elapsed_ms=$(((now - start) / 1000000))
    if devex_pane_contains "$SESSION" "$probe"; then
      if [ "$elapsed_ms" -le "$budget" ]; then
        pass "echo \"$probe\" within ${elapsed_ms}ms (budget ${budget}ms)"
      else
        fail "echo \"$probe\" took ${elapsed_ms}ms (budget ${budget}ms)"
      fi
      return 0
    fi
    # Poll cost bounds precision; a miss can overshoot by one poll interval.
    if [ "$elapsed_ms" -gt $((budget * 4 + 2000)) ]; then
      fail "echo \"$probe\" never appeared after ${elapsed_ms}ms (budget ${budget}ms)"
      return 0
    fi
    sleep 0.05
  done
}

d_expect_count_at_most() { # <n> <substring> — occurrence ceiling in last snapshot
  local limit=${1%% *} needle=${1#* } count
  needle=$(expand_tokens "$needle")
  [ -n "$LAST_SNAP" ] || { fail "expect-count-at-most \"$needle\" — no snapshot taken yet"; return; }
  count=$(grep -Fic -- "$needle" "$LAST_SNAP" || true)
  if [ "$count" -le "$limit" ]; then
    pass "$LAST_SNAP_NAME shows \"$needle\" ${count}x (limit $limit)"
  else
    fail "$LAST_SNAP_NAME shows \"$needle\" ${count}x (limit $limit)"
  fi
}

dispatch() { # <directive> <value>
  case $1 in
    name)            printf '%s\n' "$2" >> "$REPORT";;
    note)            printf '  note: %s\n' "$2" >> "$REPORT";;
    size)            d_size "$2";;
    resize)          d_resize "$2";;
    cwd)             d_cwd "$2";;
    env)             d_env "$2";;
    env-unset)       d_env_unset "$2";;
    require-env)     d_require_env "$2" || return $?;;
    require-any-env) d_require_any_env "$2" || return $?;;
    require-wrapper-flow) d_require_wrapper_flow || return $?;;
    shell)           d_shell "$2";;
    launch)          d_launch "$2";;
    launch-raw)      d_launch_raw "$2";;
    keys)            d_keys "$2";;
    type)            d_type "$2";;
    paste-file)      d_paste_file "$2";;
    submit)          d_submit "$2";;
    nav-mode)        d_nav_mode;;
    phase-result)    d_phase_result "$2";;
    wait)            d_wait "$2";;
    wait-for)        d_wait_for "$2";;
    wait-snap)       d_wait_snap "$2";;
    wait-live-snap)  d_wait_live_snap "$2";;
    require-live-snap) d_require_live_snap "$2";;
    snap)            d_snap "$2";;
    live-snap)       d_live_snap "$2";;
    saved-snap)      d_saved_snap "$2";;
    expect)          d_expect "$2";;
    expect-wide)     d_expect_wide "$2";;
    expect-not)      d_expect_not "$2";;
    expect-ansi-profile) d_expect_ansi_profile "$2";;
    expect-echo-within) d_expect_echo_within "$2";;
    expect-count-at-most) d_expect_count_at_most "$2";;
    ask)             d_ask "$2";;
    *)               devex_die "unknown directive '$1:' (in $CURRENT_FILE)";;
  esac
}

# ---------------------------------------------------------------------------
# journey loop
# ---------------------------------------------------------------------------
run_journey() { # <journey-file> <run-dir>
  CURRENT_FILE=$1
  local id line directive value declared_size rc=0 result_code result_label
  id=$(basename "$1" .journey)
  JDIR="$2/${id%%-*}"
  mkdir -p "$JDIR"
  REPORT="$JDIR/report.txt"
  : > "$REPORT"
  SESSION="kzx-devex-$(printf '%s' "${id%%-*}" | tr '[:upper:]' '[:lower:]')-$$"
  LAST_SNAP="" LAST_ANSI="" LAST_SNAP_NAME="(no snapshot yet)" SNAP_IDX=0
  PASS_N=0 FAIL_N=0 REVIEW_N=0 SESSION_STARTED=0 ENV_PREFIX=""
  J_COLS=${RUN_SIZE%x*} J_ROWS=${RUN_SIZE#*x} J_CWD=$REPO_ROOT
  TMP_HOME="" FIXTURE_TARGET=""
  ACTIVE_PROFILE="default" ACTIVE_LAUNCH_ARGS="" ACTIVE_TARGET_CONTEXT="not launched"
  ACTIVE_LAUNCH_OWNS_TERMINAL=0
  TARGET_PROOF_REQUIRED=0 TARGET_PROOF_ACTIVE=0 TARGET_REAL="" TARGET_TOPLEVEL=""
  TARGET_HEAD_BEFORE="" TARGET_STATUS_BEFORE="" TARGET_TREE_BEFORE=""
  TARGET_HEAD_AFTER="" TARGET_STATUS_AFTER="" TARGET_TREE_AFTER=""
  if grep -Eq '^require-env:[[:space:]].*KUZUSHI_DEVEX_TARGET([[:space:]]|$)' "$1"; then
    TARGET_PROOF_REQUIRED=1
  fi

  if [ -z "$SIZE_OVERRIDE" ]; then
    declared_size=$(sed -n 's/^size:[[:space:]]*//p' "$1" | head -1)
    if [ -n "$declared_size" ]; then
      J_COLS=${declared_size%x*}
      J_ROWS=${declared_size#*x}
    fi
  fi

  printf '\n=== %s — %s (%sx%s) ===\n' "$id" "$(journey_name_of "$1")" "$J_COLS" "$J_ROWS"
  while IFS= read -r line <&3 || [ -n "$line" ]; do
    case $line in ''|'#'*) continue;; esac
    directive=${line%%:*}
    value=${line#*:}; value=${value# }
    dispatch "$directive" "$value" </dev/null || { rc=$?; break; }
  done 3< "$1"

  devex_session_kill "$SESSION"
  finish_target_proof || true
  if [ "$rc" = 3 ]; then
    result_label=SKIP
    result_code=3
  else
    result_code=$(devex_journey_exit_code "$FAIL_N" "$REVIEW_N")
    result_label=$(devex_journey_result_label "$FAIL_N" "$REVIEW_N")
  fi
  {
    printf 'result: %s · %s pass / %s fail / %s review-for-human\n' \
      "$result_label" "$PASS_N" "$FAIL_N" "$REVIEW_N"
    printf 'artifacts: %s\n' "$JDIR"
  } | tee -a "$REPORT"

  return "$result_code"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
  local ids="" size_flag="" artifact_flag="" retain_flag="" retain_all=0
  SIZE_OVERRIDE=""
  while [ $# -gt 0 ]; do
    case $1 in
      -h|--help) usage;;
      --list) list_journeys; exit 0;;
      --size) shift; size_flag=$1;;
      --bin)  shift; KUZUSHI_BIN=$1;;
      --artifact-root) shift; artifact_flag=$1;;
      --retain-successful) shift; retain_flag=$1;;
      --retain-all) retain_all=1;;
      all) ids="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17";;
      [Jj]*) ids="$ids ${1#[Jj]}";;
      *) devex_log "unknown argument: $1"; usage 1;;
    esac
    shift
  done
  [ -n "$ids" ] || usage 1

  command -v tmux >/dev/null || devex_die "tmux is required (brew install tmux)"
  KUZUSHI_BIN=${KUZUSHI_BIN:-$REPO_ROOT/target/debug/kuzushi}
  [ -x "$KUZUSHI_BIN" ] \
    || devex_die "kuzushi binary not found at $KUZUSHI_BIN — build with 'cargo build -p kuzushi-cli' or set KUZUSHI_BIN"
  KUZUSHI_DEVEX_TARGET=${KUZUSHI_DEVEX_TARGET:-}
  ARTIFACT_ROOT=${artifact_flag:-${KUZUSHI_DEVEX_ARTIFACT_ROOT:-$DEFAULT_ARTIFACT_ROOT}}
  RETAIN_SUCCESSFUL=${retain_flag:-${KUZUSHI_DEVEX_RETAIN_SUCCESSFUL:-$DEFAULT_RETAIN_SUCCESSFUL}}
  case $RETAIN_SUCCESSFUL in
    ''|*[!0-9]*) devex_die "--retain-successful must be a non-negative integer";;
  esac
  SIZE_OVERRIDE=$size_flag
  RUN_SIZE=${size_flag:-$DEFAULT_SIZE}

  local run_dir stamp
  stamp=$(date +%Y%m%d-%H%M%S)
  run_dir="$ARTIFACT_ROOT/$stamp"
  mkdir -p "$run_dir"
  ln -sfn "$stamp" "$ARTIFACT_ROOT/latest"

  devex_register_cleanup

  local n rc total_fail=0 total_skip=0 total_review_required=0 summary=""
  for n in $ids; do
    rc=0
    run_journey "$(journey_file_for "J$n")" "$run_dir" || rc=$?
    case $rc in
      0) summary="$summary
  J$n  ok      ($PASS_N pass, $REVIEW_N review)";;
      "$DEVEX_REVIEW_REQUIRED_EXIT") total_review_required=$((total_review_required + 1)); summary="$summary
  J$n  REVIEW  ($PASS_N machine pass, $REVIEW_N human judgment required)";;
      3) total_skip=$((total_skip + 1)); summary="$summary
  J$n  SKIP    (missing required env)";;
      *) total_fail=$((total_fail + 1)); summary="$summary
  J$n  FAIL    ($FAIL_N failing check(s), $PASS_N pass, $REVIEW_N review)";;
    esac
  done

  printf '\n=== summary ===%s\n\nartifacts: %s\n' "$summary" "$run_dir"
  printf 'REVIEW means human judgment is still required; judge every referenced snapshot before claiming the journey passed.\n'
  local run_status=successful
  if [ "$total_fail" -gt 0 ]; then
    run_status=failed
  elif [ "$total_review_required" -gt 0 ]; then
    run_status=review
  elif [ "$total_skip" -gt 0 ]; then
    run_status=skipped
  fi
  devex_write_run_result \
    "$run_dir" "$run_status" "$total_fail" "$total_skip" "$total_review_required"
  [ "$retain_all" = 1 ] || devex_prune_successful_runs "$ARTIFACT_ROOT" "$RETAIN_SUCCESSFUL"
  [ "$total_fail" -eq 0 ] || exit 1
  [ "$total_review_required" -eq 0 ] || exit "$DEVEX_REVIEW_REQUIRED_EXIT"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
