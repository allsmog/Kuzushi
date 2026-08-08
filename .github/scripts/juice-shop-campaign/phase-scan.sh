mkdir -p "$THREAT_DIR"
cp "$THREAT_SOURCE" "$THREAT_DIR/juice-shop-adversary-model.json"
cp "$KUZUSHI_REPO/.github/campaigns/juice-shop/threat-model/README.md" \
  "$REPORT_DIR/provenance/threat-model-README.md"
cp "$THREAT_SOURCE" "$REPORT_DIR/provenance/juice-shop-adversary-model.json"
sha256sum "$THREAT_SOURCE" >"$REPORT_DIR/provenance/threat-model.sha256"

cat >"$TARGET_DIR/.kuzushi/shards.toml" <<'EOF_SHARDS'
[shards.authentication]
paths = [
  "routes/login.ts",
  "routes/2fa.ts",
  "routes/changePassword.ts",
  "routes/resetPassword.ts",
  "routes/currentUser.ts",
  "routes/authenticatedUsers.ts",
  "lib/insecurity.ts",
  "models/user.ts",
]

[shards.server-api]
paths = [
  "server.ts",
  "routes/b2bOrder.ts",
  "routes/search.ts",
  "routes/fileUpload.ts",
  "routes/profileImageUrlUpload.ts",
  "routes/redirect.ts",
  "routes/order.ts",
  "routes/dataExport.ts",
  "routes/wallet.ts",
  "routes/deluxe.ts",
]

[shards.data-models]
paths = ["data", "models", "lib"]

[shards.frontend-trust]
paths = ["frontend/src/app"]
EOF_SHARDS

PLAN_INPUT=$(python3 - <<PY
import json
print(json.dumps({
  "campaignId": "$CAMPAIGN_ID",
  "tool": "agentic-sast:scan",
  "models": ["$KUZUSHI_MODEL"],
  "modelsDir": "$THREAT_DIR",
  "maxJobs": $MODEL_SCAN_COUNT,
  "seasonPrompts": True,
  "promptOption": "AGENTIC_SAST_PROMPT",
}))
PY
)
run_required "kuzushi-campaign-plan" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run campaign:plan --input "$PLAN_INPUT"

run_required "prepare-20x-plan" python3 "$CAMPAIGN_TOOLS" prepare-plan \
  --plan "$PLAN_PATH" \
  --target "$TARGET_DIR" \
  --expected "$MODEL_SCAN_COUNT" \
  --tool-budget "$MODEL_TOOL_BUDGET_USD" \
  --job-budget "$MODEL_JOB_BUDGET_USD"
cp "$PLAN_PATH" "$REPORT_DIR/kuzushi/campaign-plan.json"

afe_checkpoint grading campaign-plan \
  "The planner produced and asserted an exact four-shard by five-threat matrix: 20 unique, separately seasoned model jobs with explicit graceful and hard budgets." \
  "kuzushi --target $TARGET_DIR campaign run $CAMPAIGN_ID" \
  campaign-planner

set +e
"$KUZUSHI_BIN" --target "$TARGET_DIR" campaign run "$CAMPAIGN_ID" \
  --workers 3 \
  --max-attempts 1 \
  --job-timeout-secs 1800 \
  --quota-wall-threshold 2 \
  --quota-wall-pause-secs 120 \
  --budget "$MODEL_SCAN_BUDGET_USD" \
  --job-budget "$MODEL_JOB_BUDGET_USD" \
  >"$REPORT_DIR/logs/kuzushi-campaign-run.log" 2>&1
CAMPAIGN_CODE=$?
set -e
cat "$REPORT_DIR/logs/kuzushi-campaign-run.log"
if [[ $CAMPAIGN_CODE -eq 0 ]]; then
  record_lane kuzushi-20x-campaign completed 0 "$REPORT_DIR/logs/kuzushi-campaign-run.log"
else
  record_lane kuzushi-20x-campaign partial "$CAMPAIGN_CODE" "$REPORT_DIR/logs/kuzushi-campaign-run.log"
fi

run_optional "kuzushi-campaign-status" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run campaign:status \
    --input "{\"campaignId\":\"$CAMPAIGN_ID\"}"
run_optional "kuzushi-campaign-coverage" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run campaign:coverage --input '{}'
run_optional "kuzushi-runs-list-pre-triage" \
  "$KUZUSHI_BIN" runs list --target "$TARGET_DIR" --json

run_optional "kuzushi-export-pre-triage" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run workspace:export-findings \
    --input '{"output":".kuzushi/v3/reports/deep-campaign/pre-triage.jsonl","format":"jsonl","completeness":"all","allowEmpty":true}'
