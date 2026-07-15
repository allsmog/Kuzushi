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
#   KUZUSHI_BIN=... KUZUSHI_DEVEX_TARGET=... override binary / @TARGET token.
#   KUZUSHI_DEVEX_ARTIFACT_ROOT=... overrides the default artifact directory.
#
# Verdicts are honest: `expect:` lines are machine-checked substrings
# (PASS/FAIL); `ask:` lines are human-judgment invariant questions emitted as
# REVIEW items next to their snapshot — never faked into a pass.
set -eo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
JOURNEY_DIR="$SCRIPT_DIR/journeys"
DEFAULT_ARTIFACT_ROOT="$SCRIPT_DIR/artifacts"
DEFAULT_SIZE="110x32"
DEFAULT_WAIT_FOR_TIMEOUT=20

# shellcheck source=lib.sh
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

# ---------------------------------------------------------------------------
# directives
# ---------------------------------------------------------------------------
ensure_session() {
  [ "$SESSION_STARTED" = 1 ] && return 0
  devex_session_start "$SESSION" "$J_COLS" "$J_ROWS" "$J_CWD"
  SESSION_STARTED=1
  sleep 0.5
}

d_size() { # COLSxROWS (ignored when --size override is set)
  [ "$SESSION_STARTED" = 1 ] && devex_die "size: must precede the first launch/keys/snap"
  [ -n "$SIZE_OVERRIDE" ] && return 0
  J_COLS=${1%x*}; J_ROWS=${1#*x}
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

d_shell() { # host-side setup command (fixture seeding etc.)
  local cmd; cmd=$(expand_tokens "$1")
  sh -c "$cmd" || fail "shell setup failed: $cmd"
}

launch_cmd() { # assemble `env -u K K=V ... <cmd>`
  local tail=$1 prefix=""
  [ -n "$ENV_PREFIX" ] && prefix="env $ENV_PREFIX"
  printf '%s' "$prefix$tail"
}

d_launch() { # args appended to the kuzushi binary ('' = bare launch)
  ensure_session
  local args cmd; args=$(expand_tokens "$1")
  ACTIVE_PROFILE=$(profile_for_launch_env "$ENV_PREFIX")
  ACTIVE_LAUNCH_ARGS=$args
  case " $args " in
    *' --target '*) ACTIVE_TARGET_CONTEXT=$args;;
    *) ACTIVE_TARGET_CONTEXT="interactive target selection from $J_CWD";;
  esac
  cmd=$(launch_cmd "$(devex_shell_quote "$KUZUSHI_BIN")${args:+ $args}")
  ENV_PREFIX=""
  devex_send_line "$SESSION" "$cmd"
  report step "launch: kuzushi${args:+ $args}"
}

d_launch_raw() { # full shell command line (pipes, --plain, non-TTY checks)
  ensure_session
  local raw cmd; raw=$(expand_tokens "$1")
  ACTIVE_PROFILE=$(profile_for_launch_env "$ENV_PREFIX")
  ACTIVE_LAUNCH_ARGS=$raw
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

d_submit() { # literal text + Enter (the common "type a verb" case)
  ensure_session
  # First Esc clears a notice/completion card or leaves Navigate mode. The
  # following F2/Esc pair then normalizes either shell input state to Prompt.
  # This remains idempotent when no modal is present and prevents typed audit
  # commands from being mistaken for view hotkeys after an acknowledgement.
  tmux send-keys -t "$SESSION" Escape F2 Escape
  devex_send_line "$SESSION" "$(expand_tokens "$1")"
  report step "submit: $1"
}

d_wait() { sleep "$1"; }

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
    if devex_pane_contains "$SESSION" "$needle"; then
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

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g; s//\\r/g'
}

canonical_file_path() {
  local dir base
  dir=$(dirname "$1")
  base=$(basename "$1")
  (cd "$dir" 2>/dev/null && printf '%s/%s' "$(pwd -P)" "$base") || printf '%s' "$1"
}

file_sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    printf '%s' unavailable
  fi
}

file_mtime_epoch() {
  stat -f '%m' "$1" 2>/dev/null || stat -c '%Y' "$1" 2>/dev/null || printf '%s' unavailable
}

write_snapshot_provenance() { # <capture-kind>
  local kind=$1 actual alt binary_path binary_version binary_hash binary_mtime
  local head dirty_count dirty timestamp tmux_version journey rendered_target
  actual=$(tmux display-message -p -t "$SESSION" '#{pane_width} #{pane_height}')
  # shellcheck disable=SC2086 # Split the trusted two-field tmux format.
  set -- $actual
  alt=$(tmux display-message -p -t "$SESSION" '#{alternate_on}')
  binary_path=$(canonical_file_path "$KUZUSHI_BIN")
  binary_version=$("$KUZUSHI_BIN" --version 2>/dev/null | head -1 || printf '%s' unavailable)
  binary_hash=$(file_sha256 "$KUZUSHI_BIN")
  binary_mtime=$(file_mtime_epoch "$KUZUSHI_BIN")
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
    printf '  "head": "%s",\n' "$(json_escape "$head")"
    printf '  "dirty": %s,\n' "$dirty"
    printf '  "dirty_entry_count": %s,\n' "$dirty_count"
    printf '  "target_context": "%s",\n' "$(json_escape "$ACTIVE_TARGET_CONTEXT")"
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

d_wait_snap_kind() { # <automatic|live> <[timeout] substring | label>
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
    if capture_pending "$requested_kind" && grep -Fiq -- "$needle" "$PENDING_SNAP"; then
      [ "$requested_kind" = automatic ] \
        && recorded_kind=$(automatic_capture_kind) \
        || recorded_kind=$requested_kind
      pass "wait-$requested_kind-snap \"$needle\" (within ${timeout}s)"
      publish_snapshot "$recorded_kind"
      return 0
    fi
    sleep 0.5; waited=$((waited + 1))
  done
  discard_pending_snapshot
  fail "wait-$requested_kind-snap \"$needle\" timed out after ${timeout}s"
}

d_wait_snap() { d_wait_snap_kind automatic "$1"; }
d_wait_live_snap() { d_wait_snap_kind live "$1"; }

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

dispatch() { # <directive> <value>
  case $1 in
    name)            printf '%s\n' "$2" >> "$REPORT";;
    note)            printf '  note: %s\n' "$2" >> "$REPORT";;
    size)            d_size "$2";;
    cwd)             d_cwd "$2";;
    env)             d_env "$2";;
    env-unset)       d_env_unset "$2";;
    require-env)     d_require_env "$2" || return $?;;
    require-any-env) d_require_any_env "$2" || return $?;;
    shell)           d_shell "$2";;
    launch)          d_launch "$2";;
    launch-raw)      d_launch_raw "$2";;
    keys)            d_keys "$2";;
    type)            d_type "$2";;
    submit)          d_submit "$2";;
    wait)            d_wait "$2";;
    wait-for)        d_wait_for "$2";;
    wait-snap)       d_wait_snap "$2";;
    wait-live-snap)  d_wait_live_snap "$2";;
    snap)            d_snap "$2";;
    live-snap)       d_live_snap "$2";;
    saved-snap)      d_saved_snap "$2";;
    expect)          d_expect "$2";;
    expect-not)      d_expect_not "$2";;
    expect-ansi-profile) d_expect_ansi_profile "$2";;
    ask)             d_ask "$2";;
    *)               devex_die "unknown directive '$1:' (in $CURRENT_FILE)";;
  esac
}

# ---------------------------------------------------------------------------
# journey loop
# ---------------------------------------------------------------------------
run_journey() { # <journey-file> <run-dir>
  CURRENT_FILE=$1
  local id line directive value declared_size rc=0
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
  {
    printf 'result: %s pass / %s fail / %s review-for-human\n' "$PASS_N" "$FAIL_N" "$REVIEW_N"
    printf 'artifacts: %s\n' "$JDIR"
  } | tee -a "$REPORT"

  [ "$rc" = 3 ] && return 3
  [ "$FAIL_N" -gt 0 ] && return 1
  return 0
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
  local ids="" size_flag="" artifact_flag=""
  SIZE_OVERRIDE=""
  while [ $# -gt 0 ]; do
    case $1 in
      -h|--help) usage;;
      --list) list_journeys; exit 0;;
      --size) shift; size_flag=$1;;
      --bin)  shift; KUZUSHI_BIN=$1;;
      --artifact-root) shift; artifact_flag=$1;;
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
  SIZE_OVERRIDE=$size_flag
  RUN_SIZE=${size_flag:-$DEFAULT_SIZE}

  local run_dir stamp
  stamp=$(date +%Y%m%d-%H%M%S)
  run_dir="$ARTIFACT_ROOT/$stamp"
  mkdir -p "$run_dir"
  ln -sfn "$stamp" "$ARTIFACT_ROOT/latest"

  devex_register_cleanup

  local n rc total_fail=0 total_skip=0 summary=""
  for n in $ids; do
    rc=0
    run_journey "$(journey_file_for "J$n")" "$run_dir" || rc=$?
    case $rc in
      0) summary="$summary
  J$n  ok      ($PASS_N pass, $REVIEW_N review)";;
      3) total_skip=$((total_skip + 1)); summary="$summary
  J$n  SKIP    (missing required env)";;
      *) total_fail=$((total_fail + 1)); summary="$summary
  J$n  FAIL    ($FAIL_N failing check(s), $PASS_N pass, $REVIEW_N review)";;
    esac
  done

  printf '\n=== summary ===%s\n\nartifacts: %s\n' "$summary" "$run_dir"
  printf 'review items are honest open questions — judge each snapshot against signifier<->state<->intent.\n'
  [ "$total_fail" -eq 0 ] || exit 1
}

main "$@"
