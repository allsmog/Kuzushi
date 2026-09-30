#!/usr/bin/env bash
# Merge per-slice match.json files into reports/<ts>/summary.md and append
# a one-line row to HISTORY.md.

set -euo pipefail

REPORT_DIR="${1:?usage: score.sh <report-dir>}"
EVAL_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [[ ! -d "$REPORT_DIR" ]]; then
  echo "score: $REPORT_DIR does not exist" >&2
  exit 2
fi

SUMMARY="$REPORT_DIR/summary.md"
HISTORY="$EVAL_DIR/reports/HISTORY.md"

# Refuse the whole summary before writing it when any slice failed or drifted.
for slice_dir in "$REPORT_DIR"/*/; do
  [[ -d "$slice_dir" ]] || continue
  node "$EVAL_DIR/../../scripts/recall-run-receipt.mjs" verify "$slice_dir"
done

ts=$(basename "$REPORT_DIR")
git_sha=$(git -C "$(git rev-parse --show-toplevel)" rev-parse --short HEAD 2>/dev/null || echo unknown)

{
  echo "# recall-eval summary — $ts"
  echo
  echo "Kuzushi commit: \`$git_sha\`"
  echo
  echo "| slice | findings | hits | misses | oracle-hit yield | recall_exact | recall_±10 | recall_fn | recall_file | usd | wall_s |"
  echo "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
} > "$SUMMARY"

agg_hits=0
agg_total=0
agg_oracle=0
agg_usd=0
agg_cost_seen=false
agg_cost_complete=true

for slice_dir in "$REPORT_DIR"/*/; do
  slice=$(basename "$slice_dir")
  match="$slice_dir/match.json"
  [[ -f "$match" ]] || continue

  findings_count=$(jq -r '.findings_total // 0' "$match")
  hits=$(jq -r '.hits // 0' "$match")
  misses=$(jq -r '.misses // 0' "$match")
  precision=$(jq -r '.oracle_hit_yield | (. * 1000 | floor / 1000)' "$match")
  recall_exact=$(jq -r '.recall.exact_line // 0 | (. * 1000 | floor / 1000)' "$match")
  recall_pm10=$(jq -r '.recall.pm_lines  // 0 | (. * 1000 | floor / 1000)' "$match")
  recall_fn=$(jq -r '.recall.function_  // .recall.function // 0 | (. * 1000 | floor / 1000)' "$match")
  recall_file=$(jq -r '.recall.file_only // 0 | (. * 1000 | floor / 1000)' "$match")
  usd=$(jq -r 'if (.cost_usd | type) == "number" then (.cost_usd * 100 | floor / 100 | tostring) else "unknown" end' "$match")
  wall=$(jq -r '.wall_seconds // 0' "$match")

  echo "| $slice | $findings_count | $hits | $misses | $precision | $recall_exact | $recall_pm10 | $recall_fn | $recall_file | $usd | $wall |" >> "$SUMMARY"

  agg_hits=$(( agg_hits + hits ))
  agg_total=$(( agg_total + findings_count ))
  agg_oracle=$(( agg_oracle + hits + misses ))
  agg_cost_seen=true
  if [[ "$usd" == "unknown" ]]; then
    agg_cost_complete=false
  else
    agg_usd=$(awk -v a="$agg_usd" -v b="$usd" 'BEGIN{printf "%.2f", a+b}')
  fi
done

if [[ "$agg_cost_seen" == true && "$agg_cost_complete" == true ]]; then
  aggregate_cost="\$$agg_usd"
else
  aggregate_cost="unknown"
fi

{
  echo
  if [[ $agg_oracle -gt 0 ]]; then
    overall_recall=$(awk -v h="$agg_hits" -v o="$agg_oracle" 'BEGIN{printf "%.3f", h/o}')
  else overall_recall="0"
  fi
  if [[ $agg_total -gt 0 ]]; then
    overall_prec=$(awk -v h="$agg_hits" -v t="$agg_total" 'BEGIN{printf "%.3f", h/t}')
  else overall_prec="0"
  fi
  echo "**Aggregate:** recall=$overall_recall oracle_hit_yield=$overall_prec total_findings=$agg_total cost=$aggregate_cost"
} >> "$SUMMARY"

# Append one row per run to HISTORY.md
if [[ ! -f "$HISTORY" ]]; then
  {
    echo "# recall-eval HISTORY"
    echo
    echo "| timestamp | kuzushi_sha | findings | hits | recall | oracle-hit yield | usd |"
    echo "|---|---|---:|---:|---:|---:|---:|"
  } > "$HISTORY"
fi
echo "| $ts | $git_sha | $agg_total | $agg_hits | $overall_recall | $overall_prec | $aggregate_cost |" >> "$HISTORY"

echo "score: wrote $SUMMARY"
echo "score: appended row to $HISTORY"
cat "$SUMMARY"
