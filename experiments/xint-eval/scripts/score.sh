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

ts=$(basename "$REPORT_DIR")
git_sha=$(git -C "$(git rev-parse --show-toplevel)" rev-parse --short HEAD 2>/dev/null || echo unknown)

{
  echo "# xint-eval summary — $ts"
  echo
  echo "Kuzushi commit: \`$git_sha\`"
  echo
  echo "| slice | findings | hits | misses | precision | recall_exact | recall_±10 | recall_fn | recall_file | proof_validated | proof_llm_only | usd | wall_s |"
  echo "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
} > "$SUMMARY"

agg_hits=0
agg_total=0
agg_oracle=0
agg_usd=0
declare -A channel_lines

for slice_dir in "$REPORT_DIR"/*/; do
  slice=$(basename "$slice_dir")
  match="$slice_dir/match.json"
  [[ -f "$match" ]] || continue

  findings_count=$(jq -r '.findings_total // 0' "$match")
  hits=$(jq -r '.hits // 0' "$match")
  misses=$(jq -r '.misses // 0' "$match")
  precision=$(jq -r '.precision // 0 | (. * 1000 | floor / 1000)' "$match")
  recall_exact=$(jq -r '.recall.exact_line // 0 | (. * 1000 | floor / 1000)' "$match")
  recall_pm10=$(jq -r '.recall.pm_lines  // 0 | (. * 1000 | floor / 1000)' "$match")
  recall_fn=$(jq -r '.recall.function_  // .recall.function // 0 | (. * 1000 | floor / 1000)' "$match")
  recall_file=$(jq -r '.recall.file_only // 0 | (. * 1000 | floor / 1000)' "$match")
  proof_validated=$(jq -r '.proof_state_breakdown.validated // 0' "$match")
  proof_llm_only=$(jq -r '.proof_state_breakdown.llm_only // 0' "$match")
  usd=$(jq -r '.cost_usd // 0 | (. * 100 | floor / 100)' "$match")
  wall=$(jq -r '.wall_seconds // 0' "$match")

  echo "| $slice | $findings_count | $hits | $misses | $precision | $recall_exact | $recall_pm10 | $recall_fn | $recall_file | $proof_validated | $proof_llm_only | $usd | $wall |" >> "$SUMMARY"

  channels=$(jq -r '.vuln_source_breakdown // {} | to_entries | map("\(.key)=\(.value)") | join(", ")' "$match")
  if [[ -n "$channels" ]]; then
    channel_lines["$slice"]="$channels"
  fi

  agg_hits=$(( agg_hits + hits ))
  agg_total=$(( agg_total + findings_count ))
  agg_oracle=$(( agg_oracle + hits + misses ))
  agg_usd=$(awk -v a="$agg_usd" -v b="$usd" 'BEGIN{printf "%.2f", a+b}')
done

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
  echo "**Aggregate:** recall=$overall_recall precision=$overall_prec total_findings=$agg_total cost=\$$agg_usd"
  if (( ${#channel_lines[@]} > 0 )); then
    echo
    echo "**Discovery channels (hit set, ±10):**"
    for slice in "${!channel_lines[@]}"; do
      echo "- \`$slice\`: ${channel_lines[$slice]}"
    done
  fi
} >> "$SUMMARY"

# Append one row per run to HISTORY.md
if [[ ! -f "$HISTORY" ]]; then
  {
    echo "# xint-eval HISTORY"
    echo
    echo "| timestamp | kuzushi_sha | findings | hits | recall | precision | usd |"
    echo "|---|---|---:|---:|---:|---:|---:|"
  } > "$HISTORY"
fi
echo "| $ts | $git_sha | $agg_total | $agg_hits | $overall_recall | $overall_prec | \$$agg_usd |" >> "$HISTORY"

echo "score: wrote $SUMMARY"
echo "score: appended row to $HISTORY"
cat "$SUMMARY"
