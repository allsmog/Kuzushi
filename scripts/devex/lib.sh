# shellcheck shell=bash
# Shared helpers for the tmux DevEx journey harness. Sourced by run-journey.sh.
# Kept macOS /bin/bash 3.2 compatible: no `set -u`, no assoc arrays, no ${var^^}.

devex_log() { printf '%s\n' "$*" >&2; }
devex_die() { devex_log "error: $*"; exit 1; }

# Exit contract shared by the standalone driver and its acceptance wrappers.
# Machine failures win; otherwise unresolved human judgments are a distinct
# outcome and must never be promoted to a clean pass.
DEVEX_REVIEW_REQUIRED_EXIT=4

devex_journey_exit_code() { # <fail-count> <review-count>
  if [ "$1" -gt 0 ]; then
    printf '%s' 1
  elif [ "$2" -gt 0 ]; then
    printf '%s' "$DEVEX_REVIEW_REQUIRED_EXIT"
  else
    printf '%s' 0
  fi
}

devex_journey_result_label() { # <fail-count> <review-count>
  case $(devex_journey_exit_code "$1" "$2") in
    0) printf '%s' PASS;;
    1) printf '%s' FAIL;;
    "$DEVEX_REVIEW_REQUIRED_EXIT") printf '%s' REVIEW_REQUIRED;;
  esac
}

devex_write_run_result() { # <run-dir> <status> <fail> <skip> <review>
  local run_dir=$1 status=$2 fail_count=$3 skip_count=$4 review_count=$5
  case $status in
    successful|failed|skipped|review) ;;
    *) devex_log "refusing to write unknown DevEx run status: $status"; return 1;;
  esac
  {
    printf '{\n'
    printf '  "status": "%s",\n' "$status"
    printf '  "failed_journeys": %s,\n' "$fail_count"
    printf '  "skipped_journeys": %s,\n' "$skip_count"
    printf '  "review_required_journeys": %s\n' "$review_count"
    printf '}\n'
  } > "$run_dir/run-result.json"
}

devex_run_result_status() { # <run-dir>
  sed -n 's/^[[:space:]]*"status":[[:space:]]*"\([^"]*\)".*/\1/p' \
    "$1/run-result.json" 2>/dev/null | head -1
}

devex_prune_successful_runs() { # <artifact-root> <retain-count>
  local artifact_root=$1 retain_count=$2 candidates candidate name kept=0 latest_target latest_name
  case $retain_count in
    ''|*[!0-9]*) devex_log "invalid successful-run retention count: $retain_count"; return 1;;
  esac
  [ -d "$artifact_root" ] || return 0

  latest_target=$(readlink "$artifact_root/latest" 2>/dev/null || true)
  latest_name=${latest_target##*/}
  candidates=$(
    for candidate in "$artifact_root"/*; do
      [ -d "$candidate" ] || continue
      [ -L "$candidate" ] && continue
      name=$(basename "$candidate")
      printf '%s\n' "$name" | grep -Eq '^[0-9]{8}-[0-9]{6}$' || continue
      [ "$(devex_run_result_status "$candidate")" = successful ] || continue
      printf '%s\n' "$name"
    done | LC_ALL=C sort -r
  )

  for name in $candidates; do
    candidate="$artifact_root/$name"
    if [ "$name" = "$latest_name" ] || [ "$kept" -lt "$retain_count" ]; then
      kept=$((kept + 1))
      continue
    fi
    # Re-check every invariant at the deletion edge. In particular, never
    # follow a directory symlink or prune evidence without an explicit pass.
    [ -d "$candidate" ] || continue
    [ -L "$candidate" ] && continue
    printf '%s\n' "$name" | grep -Eq '^[0-9]{8}-[0-9]{6}$' || continue
    [ "$(devex_run_result_status "$candidate")" = successful ] || continue
    rm -rf "$candidate"
    devex_log "pruned successful DevEx run $candidate"
  done
}

devex_report_review_count() { # <result-line>
  local count
  count=$(printf '%s' "$1" | sed -n \
    's#.* / \([0-9][0-9]*\) review-for-human.*#\1#p')
  printf '%s' "${count:-0}"
}

devex_file_contains_any() { # <file> <literal-a[ || literal-b ...]>
  local file=$1 alternatives=$2 candidate
  while :; do
    case $alternatives in
      *' || '*)
        candidate=${alternatives%% || *}
        alternatives=${alternatives#* || }
        ;;
      *)
        candidate=$alternatives
        alternatives=''
        ;;
    esac
    [ -n "$candidate" ] && grep -Fiq -- "$candidate" "$file" && return 0
    [ -n "$alternatives" ] || return 1
  done
}

devex_footer_is_navigate() { # <last-three-lines>
  case $1 in
    *'Esc dismiss'*) return 1;;
    *'Esc prompt'*|*'NAVIGATION MODE — view keys active'*) return 0;;
    *) return 1;;
  esac
}

devex_prompt_contains_draft() { # <prompt-line> <literal-draft>
  case $1 in
    *"› $2" | *"kz> $2" | *"kuzushi> $2" \
    | *"› $2  "* | *"kz> $2  "* | *"kuzushi> $2  "*) return 0;;
    *) return 1;;
  esac
}

devex_canonical_path() {
  realpath "$1" 2>/dev/null || {
    local dir base
    dir=$(dirname "$1")
    base=$(basename "$1")
    (cd "$dir" 2>/dev/null && printf '%s/%s' "$(pwd -P)" "$base")
  }
}

devex_file_sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    printf '%s' unavailable
  fi
}

devex_stdin_sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    cat >/dev/null
    printf '%s' unavailable
  fi
}

devex_is_octal_mode() { # <candidate> — a lone octal token, nothing else
  case $1 in
    ''|*[!0-7]*) return 1;;
    *) return 0;;
  esac
}

# Octal permission bits of a path. GNU `stat -c` is tried FIRST because on
# GNU, `stat -f '%Lp' <path>` means *filesystem* status: it rejects the format
# as a missing operand (exit 1) yet still prints multi-line filesystem status —
# including the volatile `Blocks: Free/Available` and `Inodes: Free` counters —
# to stdout. Chained with `||` that noise landed in every source-tree receipt
# entry, so any write anywhere on the same filesystem forged a TARGET DRIFT
# failure. On BSD/macOS `stat -c` fails with a usage error and empty stdout, so
# trying it first is safe there. Each attempt is captured separately and
# accepted only when it validates, so a rejected attempt cannot leak into the
# result; callers treat `unavailable` as a hard capture failure.
devex_path_mode() {
  local mode
  mode=$(stat -c '%a' "$1" 2>/dev/null) || mode=''
  devex_is_octal_mode "$mode" && { printf '%s' "$mode"; return 0; }
  mode=$(stat -f '%Lp' "$1" 2>/dev/null) || mode=''
  devex_is_octal_mode "$mode" && { printf '%s' "$mode"; return 0; }
  printf '%s' unavailable
}

devex_capture_target_source_status() { # <target> <receipt-path>
  LC_ALL=C git -C "$1" status --porcelain=v2 --untracked-files=all \
    -- . ':(exclude).kuzushi' > "$2"
}

devex_path_has_symlink_parent() { # <target> <relative-path>
  local current=$1 parent component
  parent=${2%/*}
  [ "$parent" != "$2" ] || return 1
  while [ -n "$parent" ]; do
    component=${parent%%/*}
    current="$current/$component"
    [ -L "$current" ] && return 0
    case $parent in
      */*) parent=${parent#*/};;
      *) parent='';;
    esac
  done
  return 1
}

# Capture a deterministic manifest of actual worktree state, not only Git's
# status classes. It covers tracked and non-ignored untracked paths, records
# type/mode/content, and hashes symlink text rather than following the link.
# Root .git and .kuzushi state is excluded from the source comparison.
devex_capture_target_source_tree() { # <target> <receipt-path>
  local target=$1 receipt=$2 paths entries rel path kind mode payload entry quoted
  paths=$(mktemp "${receipt}.paths.XXXXXX") || return 1
  entries=$(mktemp "${receipt}.entries.XXXXXX") || {
    rm -f "$paths"
    return 1
  }
  if ! git -C "$target" ls-files -z --cached --others --exclude-standard \
      -- . ':(exclude).kuzushi' > "$paths"; then
    rm -f "$paths" "$entries"
    return 1
  fi

  : > "$entries"
  # shellcheck disable=SC2094 # Error cleanup deliberately removes the loop's temporary input.
  while IFS= read -r -d '' rel; do
    case $rel in
      .git|.git/*|.kuzushi|.kuzushi/*) continue;;
    esac
    path="$target/$rel"
    if devex_path_has_symlink_parent "$target" "$rel"; then
      rm -f "$paths" "$entries"
      return 1
    fi
    mode=$(devex_path_mode "$path")
    if [ -L "$path" ]; then
      kind='symlink'
      payload=$(readlink "$path" | devex_stdin_sha256)
    elif [ -f "$path" ]; then
      kind='file'
      payload=$(devex_file_sha256 "$path")
    elif [ -d "$path" ]; then
      kind='directory'
      payload='-'
    elif [ -e "$path" ]; then
      kind='special'
      payload='-'
    else
      kind='missing'
      mode='-'
      payload='-'
    fi
    if [ "$kind" != missing ] && [ "$mode" = unavailable ]; then
      rm -f "$paths" "$entries"
      return 1
    fi
    [ "$payload" != unavailable ] || {
      rm -f "$paths" "$entries"
      return 1
    }
    entry=$(printf '%s\0%s\0%s\0%s\0' "$kind" "$mode" "$payload" "$rel" \
      | devex_stdin_sha256)
    [ "$entry" != unavailable ] || {
      rm -f "$paths" "$entries"
      return 1
    }
    quoted=$(printf '%q' "$rel")
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "$entry" "$kind" "$mode" "$payload" "$quoted" >> "$entries"
  done < "$paths"

  LC_ALL=C sort "$entries" > "$receipt"
  rm -f "$paths" "$entries"
}

devex_target_state_unchanged() { # <before-head> <before-status> <before-tree> <after-head> <after-status> <after-tree>
  [ "$1" = "$4" ] && [ "$2" = "$5" ] && [ "$3" = "$6" ]
}

devex_is_kz_wrapper_flow() { # <wrapper-path> <native-path>
  [ "$(basename "$1")" = kz ] || return 1
  [ -x "$1" ] && [ -x "$2" ] || return 1
  [ "$(devex_canonical_path "$1")" != "$(devex_canonical_path "$2")" ]
}

# ---------------------------------------------------------------------------
# tmux session lifecycle — every session we create is tracked and killed on
# exit (trap), so an aborted run never orphans a tmux session.
# ---------------------------------------------------------------------------
DEVEX_SESSIONS=""

devex_register_cleanup() {
  trap devex_cleanup_sessions EXIT INT TERM
}

devex_cleanup_sessions() {
  local s
  for s in $DEVEX_SESSIONS; do
    tmux kill-session -t "$s" 2>/dev/null || true
  done
  DEVEX_SESSIONS=""
}

# devex_session_start <name> <cols> <rows> <cwd> <native-bin> <wrapper-bin> <target>
# Starts a bare /bin/sh at a controlled size. The journey then "launches" the
# TUI by sending a command line, exactly like a real operator — this also
# survives the program exiting (the shell stays), so multi-launch journeys
# (e.g. palette matrix) reuse one session.
#
# tmux servers outlive clients and copy only their configured
# `update-environment` allowlist into new sessions. These audit identities are
# intentionally session-local so a pre-existing server cannot drop them and
# the harness never mutates the operator's tmux global environment.
devex_session_start() {
  local native_bin=${5-} wrapper_bin=${6-} target=${7-}
  tmux kill-session -t "$1" 2>/dev/null || true
  tmux new-session -d -s "$1" -x "$2" -y "$3" -c "$4" \
    -e "KUZUSHI_NATIVE_BIN=$native_bin" \
    -e "KUZUSHI_BIN=$wrapper_bin" \
    -e "KUZUSHI_DEVEX_TARGET=$target" /bin/sh \
    || devex_die "tmux new-session failed for $1"
  DEVEX_SESSIONS="$DEVEX_SESSIONS $1"
}

devex_session_kill() {
  tmux kill-session -t "$1" 2>/dev/null || true
}

devex_session_alive() {
  tmux has-session -t "$1" 2>/dev/null
}

# devex_send_line <session> <literal-text>  — type text, then Enter.
devex_send_line() {
  tmux send-keys -t "$1" -l -- "$2"
  tmux send-keys -t "$1" Enter
}

# devex_alternate_active <session>
devex_alternate_active() {
  [ "$(tmux display-message -p -t "$1" '#{alternate_on}' 2>/dev/null)" = 1 ]
}

# devex_capture_live <session> <out.txt> <out.ansi>
# Strict evidence path: fail instead of silently substituting a saved screen.
devex_capture_live() {
  devex_alternate_active "$1" || return 1
  # Capture ANSI first so a following plain content match cannot pair the
  # matched frame with a later completion.
  tmux capture-pane -t "$1" -e -p > "$3" || return 1
  tmux capture-pane -t "$1" -p > "$2"
}

# devex_capture_saved <session> <out.txt> <out.ansi>
# Explicit post-exit evidence path. An absent/empty saved alternate screen is
# an error; callers that want ordinary shell output must use devex_capture.
devex_capture_saved() {
  tmux capture-pane -t "$1" -a -q -e -p > "$3" || return 1
  tmux capture-pane -t "$1" -a -q -p > "$2" || return 1
  LC_ALL=C grep -aq '[^[:space:]]' "$2"
}

# devex_capture <session> <out.txt> <out.ansi>
# Compatibility path for mixed TUI/headless journeys. New fullscreen evidence
# should call devex_capture_live or devex_capture_saved explicitly.
devex_capture() {
  if devex_alternate_active "$1"; then
    devex_capture_live "$@"
    return
  fi
  if devex_capture_saved "$@"; then
    return
  fi
  tmux capture-pane -t "$1" -e -p > "$3"
  tmux capture-pane -t "$1" -p > "$2"
}

# devex_pane_contains <session> <fixed-substring>  (case-insensitive)
# Mixed TUI/headless path: matches the live screen, and the saved scrollback
# when no alternate screen is active. A journey that then sends keys must use
# devex_live_pane_contains instead — see below.
devex_pane_contains() {
  if [ "$(tmux display-message -p -t "$1" '#{alternate_on}' 2>/dev/null)" = 1 ]; then
    tmux capture-pane -t "$1" -p 2>/dev/null | grep -Fiq -- "$2"
  else
    tmux capture-pane -t "$1" -p 2>/dev/null | grep -Fiq -- "$2" \
      || tmux capture-pane -t "$1" -a -q -p 2>/dev/null | grep -Fiq -- "$2"
  fi
}

# devex_live_pane_contains <session> <fixed-substring>  (case-insensitive)
# Matches ONLY a screen the TUI already owns. Kuzushi enables raw mode
# immediately before entering the alternate screen, so an alternate pane is
# proof that the shell is reading keys raw.
#
# Waiting on the mixed path instead lets a needle match Kuzushi's pre-TUI boot
# banner in the scrollback — "kuzushi: choose a target in the picker; run
# `demo` for the offline fixture" matches a case-insensitive "CHOOSE A TARGET"
# — and the journey then types into a still-cooked tty, where the line
# discipline rewrites the Enter's CR to LF and the shell receives Ctrl+J.
devex_live_pane_contains() {
  devex_alternate_active "$1" || return 1
  tmux capture-pane -t "$1" -p 2>/dev/null | grep -Fiq -- "$2"
}

# devex_ansi_has_profile <capture.ansi> <indexed|truecolor>
# Looks only for SGR color forms emitted by Ratatui. Keeping this in the
# capture layer means content checks remain independent of terminal styling.
devex_ansi_has_profile() {
  local esc pattern
  esc=$(printf '\033')
  case $2 in
    indexed)   pattern="${esc}\\[[0-9;]*(38|48);5;[0-9]+m";;
    truecolor) pattern="${esc}\\[[0-9;]*(38|48);2;[0-9]+;[0-9]+;[0-9]+m";;
    *) return 2;;
  esac
  LC_ALL=C grep -aEq "$pattern" "$1"
}

# devex_shell_quote <word...>  — printf %q each word onto one line.
devex_shell_quote() {
  local out="" w
  for w in "$@"; do
    out="$out$(printf '%q' "$w") "
  done
  printf '%s' "${out% }"
}
