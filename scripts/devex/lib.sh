# Shared helpers for the tmux DevEx journey harness. Sourced by run-journey.sh.
# Kept macOS /bin/bash 3.2 compatible: no `set -u`, no assoc arrays, no ${var^^}.

devex_log() { printf '%s\n' "$*" >&2; }
devex_die() { devex_log "error: $*"; exit 1; }

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

# devex_session_start <name> <cols> <rows> <cwd>
# Starts a bare /bin/sh at a controlled size. The journey then "launches" the
# TUI by sending a command line, exactly like a real operator — this also
# survives the program exiting (the shell stays), so multi-launch journeys
# (e.g. palette matrix) reuse one session.
devex_session_start() {
  tmux kill-session -t "$1" 2>/dev/null || true
  tmux new-session -d -s "$1" -x "$2" -y "$3" -c "$4" /bin/sh \
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

# devex_capture <session> <out.txt> <out.ansi>
# Plain capture for content/honesty checks; -e capture for palette audits.
devex_capture() {
  tmux capture-pane -t "$1" -p > "$2"
  tmux capture-pane -t "$1" -e -p > "$3"
}

# devex_pane_contains <session> <fixed-substring>  (case-insensitive)
devex_pane_contains() {
  tmux capture-pane -t "$1" -p 2>/dev/null | grep -Fiq -- "$2"
}

# devex_shell_quote <word...>  — printf %q each word onto one line.
devex_shell_quote() {
  local out="" w
  for w in "$@"; do
    out="$out$(printf '%q' "$w") "
  done
  printf '%s' "${out% }"
}
