#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

: "${KUZUSHI_REPO:?KUZUSHI_REPO is required}"
: "${KUZUSHI_BIN:?KUZUSHI_BIN is required}"
: "${TARGET_DIR:?TARGET_DIR is required}"
: "${TARGET_SHA:?TARGET_SHA is required}"
: "${TARGET_BASE_SHA:?TARGET_BASE_SHA is required}"
: "${AFE_DIR:?AFE_DIR is required}"
: "${AFE_SHA:?AFE_SHA is required}"
: "${AFE_BIN:?AFE_BIN is required}"
: "${OXIDIZED_DIR:?OXIDIZED_DIR is required}"
: "${OXIDIZED_SHA:?OXIDIZED_SHA is required}"
: "${REPORT_DIR:?REPORT_DIR is required}"
: "${KUZUSHI_MODEL:?KUZUSHI_MODEL is required}"
: "${KUZUSHI_OAUTH_CREDENTIALS:?KUZUSHI_OAUTH_CREDENTIALS is required}"

MODEL_SCAN_COUNT=20
MODEL_SCAN_BUDGET_USD="${MODEL_SCAN_BUDGET_USD:-30.0}"
MODEL_TOOL_BUDGET_USD="${MODEL_TOOL_BUDGET_USD:-1.25}"
MODEL_JOB_BUDGET_USD="${MODEL_JOB_BUDGET_USD:-1.65}"
TRIAGE_BUDGET_USD="${TRIAGE_BUDGET_USD:-8.0}"
VERIFY_MAX_FINDINGS="${VERIFY_MAX_FINDINGS:-8}"
VERIFY_PASSES="${VERIFY_PASSES:-3}"

export PATH="$(dirname "$KUZUSHI_BIN"):$(dirname "$AFE_BIN"):$PATH"
export KUZUSHI_LANGGRAPH_BRIDGE="node $KUZUSHI_REPO/scripts/langgraph-bridge.mjs"
export KUZUSHI_BRIDGE_TIMEOUT_MS="1800000"
export NO_COLOR=1

CAMPAIGN_ID="juice-shop-20x-${GITHUB_RUN_ID:-local}"
AFE_RUN_ID="afe-${CAMPAIGN_ID}"
AFE_DATA="$REPORT_DIR/afe-state"
APP_IMAGE="juice-shop-20x:${GITHUB_RUN_ID:-local}"
APP_CONTAINER="juice-shop-20x-${GITHUB_RUN_ID:-local}"
NETWORK="juice-shop-20x-${GITHUB_RUN_ID:-local}"
LANE_STATUS="$REPORT_DIR/lane-status.jsonl"
KUZUSHI_REPORT_ROOT="$TARGET_DIR/.kuzushi/v3/reports/deep-campaign"
THREAT_SOURCE="$KUZUSHI_REPO/.github/campaigns/juice-shop/threat-model/juice-shop-adversary-model.json"
CAMPAIGN_TOOLS="$KUZUSHI_REPO/.github/scripts/juice-shop-campaign-tools.py"
THREAT_DIR="$TARGET_DIR/.kuzushi/v3/campaign-models"
PLAN_PATH="$TARGET_DIR/.kuzushi/v3/campaigns/$CAMPAIGN_ID/plan.json"
QUEUE_PATH="$TARGET_DIR/.kuzushi/v3/campaigns/$CAMPAIGN_ID/queue.json"

mkdir -p \
  "$REPORT_DIR/logs" \
  "$REPORT_DIR/provenance" \
  "$REPORT_DIR/static" \
  "$REPORT_DIR/dynamic" \
  "$REPORT_DIR/dynamic/schemathesis-run" \
  "$REPORT_DIR/dynamic/schemathesis-fuzz" \
  "$REPORT_DIR/dynamic/zap" \
  "$REPORT_DIR/kuzushi" \
  "$REPORT_DIR/afe" \
  "$AFE_DATA" \
  "$KUZUSHI_REPORT_ROOT"
: >"$LANE_STATUS"

exec > >(tee "$REPORT_DIR/campaign-console.log") 2>&1

cleanup() {
  set +e
  docker rm --force "$APP_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  rm -f "$KUZUSHI_OAUTH_CREDENTIALS"
  set -e
}

record_lane() {
  local lane="$1"
  local status="$2"
  local exit_code="$3"
  local detail="${4:-}"
  LANE="$lane" STATUS="$status" EXIT_CODE="$exit_code" DETAIL="$detail" \
    python3 - "$LANE_STATUS" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

with open(sys.argv[1], "a", encoding="utf-8") as handle:
    handle.write(json.dumps({
        "lane": os.environ["LANE"],
        "status": os.environ["STATUS"],
        "exitCode": int(os.environ["EXIT_CODE"]),
        "detail": os.environ.get("DETAIL", ""),
        "at": datetime.now(timezone.utc).isoformat(),
    }, sort_keys=True) + "\n")
PY
}

run_optional() {
  local lane="$1"
  shift
  local log="$REPORT_DIR/logs/${lane}.log"
  echo "::group::${lane}"
  set +e
  "$@" >"$log" 2>&1
  local code=$?
  set -e
  cat "$log"
  echo "::endgroup::"
  if [[ $code -eq 0 ]]; then
    record_lane "$lane" completed 0 "$log"
  else
    record_lane "$lane" partial "$code" "$log"
  fi
  return 0
}

run_required() {
  local lane="$1"
  shift
  local log="$REPORT_DIR/logs/${lane}.log"
  echo "::group::${lane}"
  set +e
  "$@" >"$log" 2>&1
  local code=$?
  set -e
  cat "$log"
  echo "::endgroup::"
  if [[ $code -ne 0 ]]; then
    record_lane "$lane" failed "$code" "$log"
    return "$code"
  fi
  record_lane "$lane" completed 0 "$log"
}

afe_checkpoint() {
  local phase="$1"
  local harness="$2"
  local evidence="$3"
  local next_command="$4"
  local agent="$5"
  run_optional "afe-checkpoint-${phase}" \
    "$AFE_BIN" --data-root "$AFE_DATA" campaign-checkpoint-record "$AFE_RUN_ID" \
      --target "allsmog/juice-shop@$TARGET_SHA" \
      --harness "$harness" \
      --phase "$phase" \
      --tool-evidence "$evidence" \
      --next-command "$next_command" \
      --agent "$agent"
}

afe_put() {
  local name="$1"
  local file="$2"
  [[ -f "$file" ]] || return 0
  run_optional "afe-artifact-$(echo "$name" | tr '/ ' '--')" \
    "$AFE_BIN" --data-root "$AFE_DATA" artifact-put "$AFE_RUN_ID" "$name" --file "$file"
}

cat >"$REPORT_DIR/README.md" <<EOF_README
# Juice Shop 20-scan Kuzushi campaign

- Target: allsmog/juice-shop PR #1 at \`$TARGET_SHA\`
- Baseline: \`$TARGET_BASE_SHA\`
- Model: \`$KUZUSHI_MODEL\`
- Planned non-deterministic model scans: **$MODEL_SCAN_COUNT**
- Matrix: four source shards × five threat lenses × one model
- Kuzushi: \`$(git -C "$KUZUSHI_REPO" rev-parse HEAD)\`
- Agentic Fuzz Engine: \`$AFE_SHA\`
- Oxidized Joern checkout: \`$OXIDIZED_SHA\`
- Scope: local Docker target only; no public Juice Shop instance is contacted.
- Scan budget: hard campaign ceiling \`\$$MODEL_SCAN_BUDGET_USD\`; graceful per-scan ceiling \`\$$MODEL_TOOL_BUDGET_USD\`; hard per-job backstop \`\$$MODEL_JOB_BUDGET_USD\`.
- Triage budget: \`\$$TRIAGE_BUDGET_USD\`, three independent votes per finding.
- Verification: at most \`$VERIFY_MAX_FINDINGS\` prioritized findings, \`$VERIFY_PASSES\` adversarial model passes plus a bounded empirical attempt.
- Mutation policy: no auto-patching and no source edits. Scanner/model outputs are hypotheses until triage and proof receipts corroborate them.
- Proof policy: deterministic source/CPG evidence and isolated runtime receipts are authoritative; model assessments remain advisory.
EOF_README
