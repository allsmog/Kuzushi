run_required "verify-threat-model" python3 "$CAMPAIGN_TOOLS" threat-model \
  --path "$THREAT_SOURCE" \
  --expected-scans "$MODEL_SCAN_COUNT"

python3 - "$REPORT_DIR/provenance/source-lineage.json" <<PY
import json
import os
import subprocess
import sys

out = {
  "kuzushi": subprocess.check_output(["git", "-C", os.environ["KUZUSHI_REPO"], "rev-parse", "HEAD"], text=True).strip(),
  "target": subprocess.check_output(["git", "-C", os.environ["TARGET_DIR"], "rev-parse", "HEAD"], text=True).strip(),
  "targetBase": os.environ["TARGET_BASE_SHA"],
  "agenticFuzzEngine": subprocess.check_output(["git", "-C", os.environ["AFE_DIR"], "rev-parse", "HEAD"], text=True).strip(),
  "oxidizedJoern": subprocess.check_output(["git", "-C", os.environ["OXIDIZED_DIR"], "rev-parse", "HEAD"], text=True).strip(),
  "model": os.environ["KUZUSHI_MODEL"],
  "plannedModelScans": $MODEL_SCAN_COUNT,
  "scanBudgetUsd": float("$MODEL_SCAN_BUDGET_USD"),
  "triageBudgetUsd": float("$TRIAGE_BUDGET_USD"),
  "githubRunId": os.environ.get("GITHUB_RUN_ID"),
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(out, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

run_required "verify-source-lineage" bash -c '
  test "$(git -C "$TARGET_DIR" rev-parse HEAD)" = "$TARGET_SHA"
  test "$(git -C "$AFE_DIR" rev-parse HEAD)" = "$AFE_SHA"
  test "$(git -C "$OXIDIZED_DIR" rev-parse HEAD)" = "$OXIDIZED_SHA"
  changed=$(git -C "$TARGET_DIR" diff --name-only "$TARGET_BASE_SHA" "$TARGET_SHA")
  test "$changed" = "routes/login.ts"
'

run_required "afe-campaign-start" \
  "$AFE_BIN" --data-root "$AFE_DATA" campaign-start "allsmog/juice-shop@$TARGET_SHA" --name "$AFE_RUN_ID"
run_optional "afe-runtime-doctor" "$AFE_BIN" --data-root "$AFE_DATA" runtime-doctor
run_optional "afe-runtime-backend-status" "$AFE_BIN" --data-root "$AFE_DATA" runtime-backend-status
run_optional "afe-engine-parity" "$AFE_BIN" --data-root "$AFE_DATA" engine-parity-audit
run_optional "afe-target-discover" \
  "$AFE_BIN" --data-root "$AFE_DATA" target-discover "$TARGET_DIR" --project juice-shop

afe_checkpoint readiness campaign \
  "Exact repository lineage, threat-model cardinality, AFE runtime, and backend receipts were checked before paid work." \
  "kuzushi auth ping openai-codex --model $KUZUSHI_MODEL" \
  campaign-coordinator

run_required "kuzushi-auth-ping" \
  "$KUZUSHI_BIN" auth ping openai-codex --model "$KUZUSHI_MODEL"
run_optional "kuzushi-doctor" "$KUZUSHI_BIN" doctor --target "$TARGET_DIR" --json
run_required "kuzushi-context" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run context:build --input '{}'
run_optional "kuzushi-entry-points" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run entry-points:extract --input '{}'
run_optional "kuzushi-shard-draft" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run pack:suggest-shards --input '{"emitScopes":true}'

afe_checkpoint scope source-tree \
  "Kuzushi context, entry points, and deterministic shard suggestions were captured before the fixed four-shard matrix was installed." \
  "kuzushi --target $TARGET_DIR run cpg:build" \
  source-mapper

run_required "kuzushi-cpg-build" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run cpg:build \
    --input '{"languages":"typescript,javascript","maxSourceFiles":25000}'
find "$TARGET_DIR/.kuzushi/cpg-rs" -type f -print0 2>/dev/null \
  | sort -z \
  | xargs -0 -r sha256sum >"$REPORT_DIR/provenance/cpg-sha256.txt"
cp -R "$TARGET_DIR/.kuzushi/cpg-rs" "$REPORT_DIR/kuzushi/cpg-rs" 2>/dev/null || true

afe_put "cpg-sha256.txt" "$REPORT_DIR/provenance/cpg-sha256.txt"
afe_checkpoint input-material cpg-rs \
  "JavaScript and TypeScript CPG artifacts were built with the integrated Oxidized Joern engine and digested before model scanning." \
  "kuzushi --target $TARGET_DIR run secret-scan:scan" \
  cpg-builder

run_required "kuzushi-secret-scan" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run secret-scan:scan --input '{}'
run_optional "kuzushi-semgrep" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run semgrep:scan --input '{"config":"p/owasp-top-ten"}'
