#!/usr/bin/env bash
# Run kuzushi against a single slice and persist results into the report dir.
#
# Usage: run-slice.sh <slice-name> [<report-dir>]
# If <report-dir> is omitted, a timestamped dir under experiments/xint-eval/reports/
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
  echo "  run: experiments/xint-eval/scripts/fetch-slices.sh" >&2
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
  > "$scan_json" 2> "$scan_log"
scan_status=$?
set -e

if [[ $scan_status -ne 0 ]]; then
  echo "[$SLICE] WARN: kuzushi scan exited $scan_status (see $scan_log)"
fi

"$KUZ" findings --target "$TARGET" --json > "$REPORT_DIR/$SLICE/findings.json" || true

END_TS=$(date -u +%s)
WALL=$(( END_TS - START_TS ))

# Score this slice now (per-slice score; run-all.sh also calls score.sh after all panes finish).
"$REPO_ROOT/target/release/kuzushi-eval" \
  --oracle   "$ORACLE_FILE" \
  --findings "$REPORT_DIR/$SLICE/findings.json" \
  --slice    "$SLICE" \
  --target   "$TARGET" \
  --wall-seconds "$WALL" \
  > "$REPORT_DIR/$SLICE/match.json"

cat "$REPORT_DIR/$SLICE/match.json" | jq -r '
  "[" + .slice + "] hits=" + (.hits | tostring)
  + " misses=" + (.misses | tostring)
  + " precision=" + ((.precision * 100 | floor / 100) | tostring)
  + " recall_pm10="    + ((.recall.pm_lines * 100 | floor / 100) | tostring)
  + " recall_file="    + ((.recall.file_only * 100 | floor / 100) | tostring)
  + " wall=" + (.wall_seconds | tostring) + "s"
'
