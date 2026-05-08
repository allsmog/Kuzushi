#!/usr/bin/env bash
# tmux orchestrator: spawn one window per slice, run scan + score, then merge.

set -euo pipefail

EVAL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel)"
SLICES=(linux postgres redis mariadb)

TS=$(date -u +%Y%m%dT%H%M%S)
REPORT_DIR="$EVAL_DIR/reports/$TS"
mkdir -p "$REPORT_DIR"
SESSION="recall-eval-$TS"

# Sanity: kuzushi-eval scorer must exist (Phase 0 scaffolding).
if [[ ! -x "$REPO_ROOT/target/release/kuzushi-eval" ]]; then
  echo "run-all: build kuzushi-eval first: cargo build --release -p kuzushi-eval" >&2
  exit 2
fi

if [[ ! -x "$REPO_ROOT/target/release/kuzushi" ]]; then
  echo "run-all: build kuzushi first: cargo build --release -p kuzushi-cli" >&2
  exit 2
fi

# First slice opens the session; subsequent slices add windows.
first="${SLICES[0]}"
rest=("${SLICES[@]:1}")

cmd_for_slice() {
  local s="$1"
  printf 'bash %q %q %q ; echo "[%s] done — press any key to close" ; read -n1' \
    "$EVAL_DIR/scripts/run-slice.sh" "$s" "$REPORT_DIR" "$s"
}

echo "[recall-eval] tmux session=$SESSION report=$REPORT_DIR"

tmux new-session -d -s "$SESSION" -n "$first" "$(cmd_for_slice "$first")"
tmux set-option -t "$SESSION" remain-on-exit on
tmux set-option -t "$SESSION" history-limit 50000

for s in "${rest[@]}"; do
  tmux new-window -t "$SESSION" -n "$s" "$(cmd_for_slice "$s")"
done

# Add a monitor window
tmux new-window -t "$SESSION" -n monitor \
  "watch -n 5 ls $REPORT_DIR; bash"

echo "[recall-eval] attach with: tmux attach -t $SESSION"
echo "[recall-eval] panes will remain after exit; close with: tmux kill-session -t $SESSION"

# Wait for all per-slice panes to die, leaving the monitor pane alone.
echo "[recall-eval] waiting for slice panes to complete…"
while true; do
  alive=0
  for s in "${SLICES[@]}"; do
    if tmux list-panes -t "$SESSION:$s" -F '#{pane_dead}' 2>/dev/null | grep -q '^0$'; then
      alive=$(( alive + 1 ))
    fi
  done
  if [[ $alive -eq 0 ]]; then break; fi
  sleep 30
done

echo "[recall-eval] all slice panes complete; running aggregate scorer"
"$EVAL_DIR/scripts/score.sh" "$REPORT_DIR"

echo "[recall-eval] summary: $REPORT_DIR/summary.md"
