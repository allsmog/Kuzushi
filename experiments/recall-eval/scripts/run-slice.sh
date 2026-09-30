#!/usr/bin/env bash
# Run kuzushi against a single slice and persist results into the report dir.
#
# Usage: run-slice.sh <slice-name> [<report-dir>]
# If <report-dir> is omitted, a timestamped dir under experiments/recall-eval/reports/
# is created.

set -euo pipefail

SLICE="${1:?usage: run-slice.sh <slice-name> [<report-dir>]}"
EVAL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel)"
KUZ="${KUZUSHI_BIN:-$REPO_ROOT/target/release/kuzushi}"

TARGET="$EVAL_DIR/slices/$SLICE"
ORACLE_GLOB="$EVAL_DIR/oracles/*-${SLICE}-*.json $EVAL_DIR/oracles/${SLICE}*.json"

if [[ ! -d "$TARGET" ]]; then
  echo "run-slice: slice $SLICE not populated at $TARGET" >&2
  echo "  run: experiments/recall-eval/scripts/fetch-slices.sh" >&2
  exit 2
fi

ORACLE_FILE=""
for cand in $ORACLE_GLOB; do
  [[ -f "$cand" ]] && { ORACLE_FILE="$cand"; break; }
done
if [[ -z "$ORACLE_FILE" ]]; then
  echo "run-slice: no oracle found for $SLICE under $EVAL_DIR/oracles/" >&2
  exit 2
fi

REPORT_DIR="${2:-$EVAL_DIR/reports/$(date -u +%Y%m%dT%H%M%S)}"
mkdir -p "$REPORT_DIR/$SLICE"
REPORT_DIR="$(cd "$REPORT_DIR" && pwd)"
RECEIPT="$REPORT_DIR/$SLICE/validity.json"
RECEIPT_TOOL="$REPO_ROOT/scripts/recall-run-receipt.mjs"
if [[ -e "$RECEIPT" || -e "$REPORT_DIR/$SLICE/match.json" ]]; then
  echo "run-slice: use a fresh report directory for each benchmark run" >&2
  exit 2
fi
mark_invalid() {
  jq -n --arg stage "$1" --argjson exit_code "$2" \
    '{schemaVersion:1,status:"invalid",stage:$stage,exitCode:$exit_code}' > "$RECEIPT"
}
if node "$RECEIPT_TOOL" prepare "$TARGET" "$ORACLE_FILE" "$EVAL_DIR/scope/$SLICE.txt" "$RECEIPT"; then
  :
else
  status=$?
  mark_invalid provenance "$status"
  exit "$status"
fi
START_TS=$(date -u +%s)

# Default to scan task names supported by current main. Override with
# KUZUSHI_EVAL_TASKS for branch-specific engines.
TASKS="${KUZUSHI_EVAL_TASKS:-systems-hunt,carlini-threat-hunt,taint-iris-next}"

# Honour OAuth env variables if set; let kuzushi config defaults do the rest.
export KUZUSHI_OAUTH_CREDENTIALS="${KUZUSHI_OAUTH_CREDENTIALS:-$HOME/.kuzushi/oauth-credentials.json}"

echo "[$SLICE] target=$TARGET tasks=$TASKS"
echo "[$SLICE] report=$REPORT_DIR/$SLICE"
echo "[$SLICE] kuzushi=$KUZ"

scan_log="$REPORT_DIR/$SLICE/scan.log"
scan_json="$REPORT_DIR/$SLICE/scan.json"

set +e
"$KUZ" scan "$TARGET" \
  --tasks "$TASKS" \
  --triage \
  --json \
  --sarif "$REPORT_DIR/$SLICE/scan.sarif" \
  > "$scan_json" 2> "$scan_log"
scan_status=$?
set -e

if [[ $scan_status -ne 0 ]]; then
  mark_invalid scan "$scan_status"
  echo "[$SLICE] invalid benchmark: scan exited $scan_status (see $scan_log)" >&2
  exit "$scan_status"
fi

if node "$RECEIPT_TOOL" complete "$TARGET" "$ORACLE_FILE" "$EVAL_DIR/scope/$SLICE.txt" "$RECEIPT" \
  "$scan_json" "$REPORT_DIR/$SLICE/scan.sarif" "$REPORT_DIR/$SLICE/findings.json"; then
  :
else
  status=$?
  mark_invalid export "$status"
  exit "$status"
fi
COST_ARGS=()
exact_cost=$(jq -r '.cost.exactUsd // empty' "$RECEIPT")
if [[ -n "$exact_cost" ]]; then COST_ARGS=(--cost-usd "$exact_cost"); fi

END_TS=$(date -u +%s)
WALL=$(( END_TS - START_TS ))

# Score this slice now (per-slice score; run-all.sh also calls score.sh after all panes finish).
"$REPO_ROOT/target/release/kuzushi-eval" \
  --oracle   "$ORACLE_FILE" \
  --findings "$REPORT_DIR/$SLICE/findings.json" \
  --slice    "$SLICE" \
  --target   "$TARGET" \
  --wall-seconds "$WALL" \
  --enforce-threshold \
  "${COST_ARGS[@]}" \
  > "$REPORT_DIR/$SLICE/match.json"

cat "$REPORT_DIR/$SLICE/match.json" | jq -r '
  "[" + .slice + "] hits=" + (.hits | tostring)
  + " misses=" + (.misses | tostring)
  + " oracle_hit_yield=" + ((.oracle_hit_yield * 100 | floor / 100) | tostring)
  + " recall_pm10="    + ((.recall.pm_lines * 100 | floor / 100) | tostring)
  + " recall_file="    + ((.recall.file_only * 100 | floor / 100) | tostring)
  + " wall=" + (.wall_seconds | tostring) + "s"
'
