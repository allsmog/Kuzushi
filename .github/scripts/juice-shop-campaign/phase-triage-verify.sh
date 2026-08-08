DEDUPE_INPUT=$(python3 - <<PY
import json
print(json.dumps({
  "maxGroups": 64,
  "maxCandidates": 300,
  "maxEscalations": 12,
  "dryRun": False,
  "model": "$KUZUSHI_MODEL",
}))
PY
)
run_optional "kuzushi-triage-dedupe" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run triage:dedupe --input "$DEDUPE_INPUT"

TRIAGE_INPUT=$(python3 - <<PY
import json
print(json.dumps({
  "scope": "all",
  "dedupe": False,
  "votes": 3,
  "strategy": "deep",
  "taintTools": "available",
  "concurrency": 3,
  "costCapUsd": float("$TRIAGE_BUDGET_USD"),
  "maxSteps": 20,
  "depositUsd": 0.75,
  "passes": 1,
  "temperature": 0.25,
  "model": "$KUZUSHI_MODEL",
}))
PY
)
run_optional "kuzushi-triage-three-vote" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run triage:run --input "$TRIAGE_INPUT"

CHAIN_INPUT=$(python3 - <<PY
import json
print(json.dumps({"maxChains": 12, "model": "$KUZUSHI_MODEL"}))
PY
)
run_optional "kuzushi-triage-chain-hunt" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run triage:chain-hunt --input "$CHAIN_INPUT"

afe_checkpoint reachability source-runtime-corroboration \
  "Twenty independently seasoned scans were folded with deterministic and runtime evidence, then corpus-deduplicated and triaged by three-vote code-reading review without auto-patching." \
  "workspace:export-findings post-triage.jsonl" \
  evidence-correlator

run_optional "kuzushi-export-post-triage" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run workspace:export-findings \
    --input '{"output":".kuzushi/v3/reports/deep-campaign/post-triage.jsonl","format":"jsonl","completeness":"all","allowEmpty":true}'

POST_TRIAGE="$KUZUSHI_REPORT_ROOT/post-triage.jsonl"
VERIFY_CANDIDATES="$REPORT_DIR/kuzushi/verify-candidates.tsv"
run_required "select-verification-candidates" python3 "$CAMPAIGN_TOOLS" select-verification \
  --source "$POST_TRIAGE" \
  --out "$VERIFY_CANDIDATES" \
  --limit "$VERIFY_MAX_FINDINGS"

if [[ -s "$VERIFY_CANDIDATES" ]]; then
  while IFS=$'\t' read -r ordinal fingerprint severity verdict confidence corroboration title; do
    VERIFY_INPUT=$(FINGERPRINT="$fingerprint" python3 - <<PY
import json
import os
print(json.dumps({
  "fingerprint": os.environ["FINGERPRINT"],
  "passes": int("$VERIFY_PASSES"),
  "model": "$KUZUSHI_MODEL",
  "mcps": True,
  "mcpToolTimeoutMs": 120000,
}))
PY
)
    run_optional "verify-model-$(printf '%02d' "$ordinal")" \
      "$KUZUSHI_BIN" --target "$TARGET_DIR" run verify:finding --input "$VERIFY_INPUT"
    EMPIRICAL_INPUT=$(FINGERPRINT="$fingerprint" python3 - <<'PY'
import json
import os
print(json.dumps({"fingerprint": os.environ["FINGERPRINT"]}))
PY
)
    run_optional "verify-empirical-$(printf '%02d' "$ordinal")" \
      "$KUZUSHI_BIN" --target "$TARGET_DIR" run verify:exploit --input "$EMPIRICAL_INPUT"
  done <"$VERIFY_CANDIDATES"
else
  record_lane verification-selection skipped 0 "No high-priority triaged findings met the verification threshold"
fi

afe_checkpoint dedupe findings-ledger \
  "The canonical findings ledger retained cross-tool identities and explicit triage states; the verification candidate list was ranked without converting model confidence into proof." \
  "verify:finding and verify:exploit" \
  dedupe-reviewer

afe_checkpoint patch no-source-mutation \
  "Auto-patching remained disabled. Model and empirical verifiers evaluated the exact PR commit without changing tracked source." \
  "workspace:export-findings final" \
  patch-governor

run_optional "kuzushi-export-final-jsonl" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run workspace:export-findings \
    --input '{"output":".kuzushi/v3/reports/deep-campaign/findings.jsonl","format":"jsonl","completeness":"all","allowEmpty":true}'
run_optional "kuzushi-export-final-sarif" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run workspace:export-findings \
    --input '{"output":".kuzushi/v3/reports/deep-campaign/findings.sarif","format":"sarif","completeness":"all","allowEmpty":true}'
run_optional "kuzushi-export-final-markdown" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run workspace:export-findings \
    --input '{"output":".kuzushi/v3/reports/deep-campaign/markdown","format":"markdown-bundle","completeness":"all","allowEmpty":true}'
run_optional "kuzushi-runs-list-final" \
  "$KUZUSHI_BIN" runs list --target "$TARGET_DIR" --json

cp -R "$KUZUSHI_REPORT_ROOT" "$REPORT_DIR/kuzushi/export" 2>/dev/null || true
cp -R "$TARGET_DIR/.kuzushi/v3/campaigns/$CAMPAIGN_ID" "$REPORT_DIR/kuzushi/campaign" 2>/dev/null || true
cp -R "$TARGET_DIR/.kuzushi/v3/runs" "$REPORT_DIR/kuzushi/runs" 2>/dev/null || true

afe_put "kuzushi-findings.jsonl" "$KUZUSHI_REPORT_ROOT/findings.jsonl"
afe_put "kuzushi-findings.sarif" "$KUZUSHI_REPORT_ROOT/findings.sarif"
afe_put "kuzushi-campaign-plan.json" "$PLAN_PATH"
afe_put "verification-candidates.tsv" "$VERIFY_CANDIDATES"
