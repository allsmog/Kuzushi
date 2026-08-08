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

export PATH="$(dirname "$KUZUSHI_BIN"):$(dirname "$AFE_BIN"):$PATH"
export KUZUSHI_LANGGRAPH_BRIDGE="node $KUZUSHI_REPO/scripts/langgraph-bridge.mjs"
export KUZUSHI_BRIDGE_TIMEOUT_MS="1200000"
export NO_COLOR=1

CAMPAIGN_ID="juice-shop-20x-${GITHUB_RUN_ID:-local}"
AFE_RUN_ID="afe-${CAMPAIGN_ID}"
AFE_DATA="$REPORT_DIR/afe-state"
APP_IMAGE="juice-shop-20x:${GITHUB_RUN_ID:-local}"
APP_CONTAINER="juice-shop-20x-${GITHUB_RUN_ID:-local}"
NETWORK="juice-shop-20x-${GITHUB_RUN_ID:-local}"
LANE_STATUS="$REPORT_DIR/lane-status.jsonl"
KUZUSHI_EXPORT_REL=".kuzushi/v3/reports/juice-shop-20x"
KUZUSHI_EXPORT_ROOT="$TARGET_DIR/$KUZUSHI_EXPORT_REL"
CAMPAIGN_INPUT_REL=".kuzushi/v3/campaign-inputs"
CAMPAIGN_INPUT_ROOT="$TARGET_DIR/$CAMPAIGN_INPUT_REL"
MODELS_ROOT="$TARGET_DIR/.kuzushi/v3/campaign-models"
THREAT_MODEL_SOURCE="$KUZUSHI_REPO/.github/campaign/juice-shop-threat-model.json"
TRIAGE_PROMPT_SOURCE="$KUZUSHI_REPO/.github/campaign/juice-shop-triage-prompt.md"
VERIFY_PROMPT_SOURCE="$KUZUSHI_REPO/.github/campaign/juice-shop-verify-prompt.md"
TRIAGE_PROMPT_REL="$CAMPAIGN_INPUT_REL/triage.md"
VERIFY_PROMPT_REL="$CAMPAIGN_INPUT_REL/verify.md"
PLAN_PATH="$TARGET_DIR/.kuzushi/v3/campaigns/$CAMPAIGN_ID/plan.json"
INDEPENDENCE_MANIFEST="$REPORT_DIR/kuzushi/independence-manifest.json"
POST_TRIAGE_REL="$KUZUSHI_EXPORT_REL/post-triage-findings.jsonl"
POST_TRIAGE_FINDINGS="$TARGET_DIR/$POST_TRIAGE_REL"
FINAL_FINDINGS_REL="$KUZUSHI_EXPORT_REL/findings.jsonl"
FINAL_FINDINGS="$TARGET_DIR/$FINAL_FINDINGS_REL"
MODEL_QUEUE="$REPORT_DIR/verification/model-queue.jsonl"
EMPIRICAL_QUEUE="$REPORT_DIR/verification/empirical-queue.jsonl"
VERIFICATION_SELECTION="$REPORT_DIR/verification/selection-summary.json"
RUNTIME_PROBE_OUTPUT="$REPORT_DIR/dynamic/runtime-probes.json"
RUNTIME_PROBE_FINDINGS="$REPORT_DIR/dynamic/runtime-probe-findings.jsonl"
ZAP_FINDINGS="$REPORT_DIR/dynamic/zap-findings.jsonl"
DYNAMIC_FINDINGS="$REPORT_DIR/dynamic/dynamic-findings.jsonl"

LAST_EXIT_CODE=0

mkdir -p \
  "$REPORT_DIR/logs" \
  "$REPORT_DIR/provenance" \
  "$REPORT_DIR/static" \
  "$REPORT_DIR/dynamic/schemathesis-run" \
  "$REPORT_DIR/dynamic/schemathesis-fuzz" \
  "$REPORT_DIR/dynamic/zap" \
  "$REPORT_DIR/kuzushi" \
  "$REPORT_DIR/verification/model" \
  "$REPORT_DIR/verification/empirical" \
  "$REPORT_DIR/afe" \
  "$AFE_DATA" \
  "$KUZUSHI_EXPORT_ROOT" \
  "$CAMPAIGN_INPUT_ROOT" \
  "$MODELS_ROOT"
: >"$LANE_STATUS"
: >"$RUNTIME_PROBE_FINDINGS"
: >"$ZAP_FINDINGS"
: >"$DYNAMIC_FINDINGS"

exec > >(tee "$REPORT_DIR/campaign-console.log") 2>&1

cleanup() {
  set +e
  docker rm --force "$APP_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  rm -f "$KUZUSHI_OAUTH_CREDENTIALS"
  set -e
}
trap cleanup EXIT

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

path = sys.argv[1]
row = {
    "lane": os.environ["LANE"],
    "status": os.environ["STATUS"],
    "exitCode": int(os.environ["EXIT_CODE"]),
    "detail": os.environ.get("DETAIL", ""),
    "at": datetime.now(timezone.utc).isoformat(),
}
with open(path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(row, sort_keys=True) + "\n")
PY
}

run_logged() {
  local required="$1"
  local lane="$2"
  shift 2
  local log="$REPORT_DIR/logs/${lane}.log"
  echo "::group::${lane}"
  set +e
  "$@" >"$log" 2>&1
  LAST_EXIT_CODE=$?
  set -e
  cat "$log"
  echo "::endgroup::"
  if [[ $LAST_EXIT_CODE -eq 0 ]]; then
    record_lane "$lane" completed 0 "$log"
    return 0
  fi
  if [[ "$required" == "required" ]]; then
    record_lane "$lane" failed "$LAST_EXIT_CODE" "$log"
    return "$LAST_EXIT_CODE"
  fi
  record_lane "$lane" partial "$LAST_EXIT_CODE" "$log"
  return 0
}

run_required() {
  run_logged required "$@"
}

run_optional() {
  run_logged optional "$@"
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

copy_campaign_inputs() {
  cp "$THREAT_MODEL_SOURCE" "$MODELS_ROOT/juice-shop-threat-model.json"
  cp "$TRIAGE_PROMPT_SOURCE" "$TARGET_DIR/$TRIAGE_PROMPT_REL"
  cp "$VERIFY_PROMPT_SOURCE" "$TARGET_DIR/$VERIFY_PROMPT_REL"
  cp "$THREAT_MODEL_SOURCE" "$REPORT_DIR/static/juice-shop-threat-model.json"
  cp "$TRIAGE_PROMPT_SOURCE" "$REPORT_DIR/static/juice-shop-triage-prompt.md"
  cp "$VERIFY_PROMPT_SOURCE" "$REPORT_DIR/static/juice-shop-verify-prompt.md"
}

write_shard_manifest() {
  mkdir -p "$TARGET_DIR/.kuzushi"
  cat >"$TARGET_DIR/.kuzushi/shards.toml" <<'EOF'
[shards.authentication_identity]
paths = [
  "routes/login.ts",
  "routes/2fa.ts",
  "routes/changePassword.ts",
  "routes/resetPassword.ts",
  "routes/authenticatedUsers.ts",
  "routes/currentUser.ts",
  "routes/securityQuestion.ts",
  "routes/saveLoginIp.ts",
  "lib/insecurity.ts",
  "models/user.ts",
]

[shards.business_objects_api]
paths = [
  "routes/b2bOrder.ts",
  "routes/basket.ts",
  "routes/basketItems.ts",
  "routes/address.ts",
  "routes/payment.ts",
  "routes/order.ts",
  "routes/orderHistory.ts",
  "routes/delivery.ts",
  "routes/wallet.ts",
  "routes/coupon.ts",
  "routes/deluxe.ts",
  "routes/recycles.ts",
  "models",
]

[shards.files_parsers_server]
paths = [
  "server.ts",
  "routes/fileUpload.ts",
  "routes/profileImageUrlUpload.ts",
  "routes/profileImageFileUpload.ts",
  "routes/fileServer.ts",
  "routes/logfileServer.ts",
  "routes/quarantineServer.ts",
  "routes/keyServer.ts",
  "routes/redirect.ts",
  "routes/dataExport.ts",
  "routes/dataErasure.ts",
  "routes/search.ts",
  "routes/chat.ts",
  "routes/memory.ts",
  "lib",
]

[shards.browser_state_privacy]
paths = [
  "frontend/src/app",
  "routes/angular.ts",
  "routes/userProfile.ts",
  "routes/updateUserProfile.ts",
  "routes/createProductReviews.ts",
  "routes/updateProductReviews.ts",
  "routes/showProductReviews.ts",
  "routes/likeProductReviews.ts",
  "routes/appConfiguration.ts",
]
EOF
  cp "$TARGET_DIR/.kuzushi/shards.toml" "$REPORT_DIR/static/shards.toml"
}

write_campaign_readme() {
  cat >"$REPORT_DIR/README.md" <<EOF
# Juice Shop 20× independent Kuzushi campaign

- Target: \`allsmog/juice-shop\` PR #1 at \`$TARGET_SHA\`
- Baseline: \`$TARGET_BASE_SHA\`
- Model: \`$KUZUSHI_MODEL\`
- Planned independent scans: **20**
- Scan construction: **4 source shards × 5 threat lenses**
- Kuzushi source: \`$(git -C "$KUZUSHI_REPO" rev-parse HEAD)\`
- Agentic Fuzz Engine source: \`$AFE_SHA\`
- Requested Oxidized Joern source: \`$OXIDIZED_SHA\`
- Execution scope: local source plus a Dockerized Juice Shop instance bound to loopback and an internal Docker network.
- Source mutation policy: disabled. The campaign does not patch the target.
- Independence controls: one unique shard/threat cell per job, random prompt nonce, independently shuffled per-job scope ordering, no inherited verdicts, and post-scan-only corpus triage.
- Triage: model dedupe followed by five independent votes per finding using deep review and CPG-backed navigation.
- Verification: independent model panel followed by the deterministic \`verify:exploit\` lane and bounded application-level probes.
- Proof policy: scanner and model output are hypotheses; runtime receipts and source-grounded verification remain distinct.
EOF
}

write_provenance() {
  python3 - "$REPORT_DIR/provenance/source-lineage.json" <<'PY'
import json
import os
import subprocess
import sys

def git_sha(path: str) -> str:
    return subprocess.check_output(["git", "-C", path, "rev-parse", "HEAD"], text=True).strip()

document = {
    "schemaVersion": 1,
    "kuzushi": git_sha(os.environ["KUZUSHI_REPO"]),
    "target": git_sha(os.environ["TARGET_DIR"]),
    "targetBase": os.environ["TARGET_BASE_SHA"],
    "agenticFuzzEngine": git_sha(os.environ["AFE_DIR"]),
    "oxidizedJoernRequested": git_sha(os.environ["OXIDIZED_DIR"]),
    "model": os.environ["KUZUSHI_MODEL"],
    "githubRunId": os.environ.get("GITHUB_RUN_ID"),
    "scanCountRequested": 20,
    "sourceMutationAllowed": False,
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(document, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

normalize_zap_reports() {
  python3 - "$REPORT_DIR/dynamic/zap" "$ZAP_FINDINGS" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
risk_map = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}
rows = []
for report in (root / "api-report.json", root / "full-report.json"):
    if not report.is_file():
        continue
    try:
        document = json.loads(report.read_text(encoding="utf-8"))
    except Exception:
        continue
    for site in document.get("site", []):
        for alert in site.get("alerts", []):
            instances = alert.get("instances") or [{}]
            for instance in instances[:25]:
                uri = str(instance.get("uri") or site.get("@name") or "runtime")
                cwe = str(alert.get("cweid") or "").strip()
                risk = str(alert.get("riskdesc") or "").split(" ")[0]
                row = {
                    "file": "runtime/" + uri.replace("://", "/").lstrip("/")[:300],
                    "line": 1,
                    "title": f"ZAP: {alert.get('alert') or alert.get('name') or 'HTTP security alert'}",
                    "severity": risk_map.get(risk, "info"),
                    "class": "isolated-dynamic-zap",
                }
                if cwe and cwe != "-1":
                    row["cwe"] = f"CWE-{cwe}"
                rows.append(row)
seen = set()
with out.open("w", encoding="utf-8") as handle:
    for row in rows:
        key = (row["file"], row["title"], row.get("cwe"))
        if key in seen:
            continue
        seen.add(key)
        handle.write(json.dumps(row, sort_keys=True) + "\n")
PY
}

export_findings_with_policy() {
  local policy="$1"
  local lane="$2"
  local output_rel="$3"
  local format="$4"
  "$policy" "$lane" \
    "$KUZUSHI_BIN" --target "$TARGET_DIR" run workspace:export-findings \
      --input "$(python3 - "$output_rel" "$format" <<'PY'
import json
import sys
print(json.dumps({
    "output": sys.argv[1],
    "format": sys.argv[2],
    "completeness": "all",
    "allowEmpty": True,
}))
PY
)"
}

export_findings_required() {
  export_findings_with_policy run_required "$@"
}

export_findings_optional() {
  export_findings_with_policy run_optional "$@"
}

copy_kuzushi_evidence() {
  rm -rf "$REPORT_DIR/kuzushi/state"
  mkdir -p "$REPORT_DIR/kuzushi/state"
  for path in \
    "$TARGET_DIR/.kuzushi/v3/campaigns/$CAMPAIGN_ID" \
    "$TARGET_DIR/.kuzushi/v3/runs" \
    "$TARGET_DIR/.kuzushi/v3/reports" \
    "$TARGET_DIR/.kuzushi/cpg-rs" \
    "$TARGET_DIR/.kuzushi/trend-history.jsonl" \
    "$TARGET_DIR/.kuzushi/findings.db"; do
    if [[ -e "$path" ]]; then
      cp -R "$path" "$REPORT_DIR/kuzushi/state/" 2>/dev/null || true
    fi
  done
}

copy_campaign_inputs
write_shard_manifest
write_campaign_readme
write_provenance

run_required "verify-source-lineage" bash -c '
  test "$(git -C "$TARGET_DIR" rev-parse HEAD)" = "$TARGET_SHA"
  test "$(git -C "$AFE_DIR" rev-parse HEAD)" = "$AFE_SHA"
  test "$(git -C "$OXIDIZED_DIR" rev-parse HEAD)" = "$OXIDIZED_SHA"
  changed=$(git -C "$TARGET_DIR" diff --name-only "$TARGET_BASE_SHA" "$TARGET_SHA")
  test "$changed" = "routes/login.ts"
  test -z "$(git -C "$TARGET_DIR" status --porcelain --untracked-files=no)"
'

run_required "afe-campaign-start" \
  "$AFE_BIN" --data-root "$AFE_DATA" campaign-start "allsmog/juice-shop@$TARGET_SHA" --name "$AFE_RUN_ID"
run_optional "afe-runtime-doctor" "$AFE_BIN" --data-root "$AFE_DATA" runtime-doctor
run_optional "afe-runtime-backend-status" "$AFE_BIN" --data-root "$AFE_DATA" runtime-backend-status
run_optional "afe-engine-parity" "$AFE_BIN" --data-root "$AFE_DATA" engine-parity-audit
run_optional "afe-target-discover" \
  "$AFE_BIN" --data-root "$AFE_DATA" target-discover "$TARGET_DIR" --project juice-shop

afe_checkpoint readiness campaign \
  "Pinned repository lineage verified; AFE runtime and backend receipts captured." \
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
  "Kuzushi context, entry points, and the explicit four-shard manifest are available." \
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

run_required "kuzushi-secret-scan" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run secret-scan:scan --input '{}'
run_optional "kuzushi-semgrep" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run semgrep:scan \
    --input '{"config":"p/owasp-top-ten"}'

afe_checkpoint input-material cpg-rs \
  "TypeScript and JavaScript CPG artifacts plus deterministic scanner receipts are recorded." \
  "docker build juice-shop" \
  cpg-builder

run_required "docker-build-target" docker build --pull=false --tag "$APP_IMAGE" "$TARGET_DIR"
run_required "docker-network" docker network create --internal "$NETWORK"
run_required "docker-start-target" docker run --detach \
  --name "$APP_CONTAINER" \
  --network "$NETWORK" \
  --network-alias juice-shop-campaign \
  --publish 127.0.0.1:3000:3000 \
  "$APP_IMAGE"

run_required "target-readiness" bash -c '
  ready=0
  for attempt in $(seq 1 120); do
    if curl --fail --silent --show-error http://127.0.0.1:3000/ >/dev/null; then
      ready=1
      break
    fi
    sleep 2
  done
  test "$ready" -eq 1
'

run_required "bounded-runtime-probes" env \
  JUICE_SHOP_URL="http://127.0.0.1:3000" \
  RUNTIME_PROBE_OUTPUT="$RUNTIME_PROBE_OUTPUT" \
  RUNTIME_PROBE_FINDINGS="$RUNTIME_PROBE_FINDINGS" \
  node "$KUZUSHI_REPO/.github/scripts/juice-shop-runtime-probes.mjs"

ADMIN_TOKEN=$(curl --fail --silent --show-error \
  -H 'content-type: application/json' \
  --data '{"email":"admin@juice-sh.op","password":"admin123"}' \
  http://127.0.0.1:3000/rest/user/login \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["authentication"]["token"])')
test -n "$ADMIN_TOKEN"

cp "$TARGET_DIR/swagger.yml" "$REPORT_DIR/dynamic/zap/openapi.yml"
sed -i 's#url: /b2b/v2#url: http://juice-shop-campaign:3000/b2b/v2#' \
  "$REPORT_DIR/dynamic/zap/openapi.yml"

set +e
timeout --signal=TERM 720s docker run --rm \
  --network "$NETWORK" \
  -v "$TARGET_DIR/swagger.yml:/app/openapi.yml:ro" \
  -v "$REPORT_DIR/dynamic/schemathesis-run:/app/schemathesis-report:rw" \
  -e SCHEMATHESIS_COVERAGE_REPORT_HTML_PATH=/app/schemathesis-report/schema-coverage.html \
  ghcr.io/schemathesis/schemathesis:stable \
  --no-color run -w 4 /app/openapi.yml \
    --url http://juice-shop-campaign:3000/b2b/v2 \
    --header "Authorization: Bearer $ADMIN_TOKEN" \
    --mode all \
    --max-examples 150 \
    --continue-on-failure \
    --report junit \
  >"$REPORT_DIR/logs/schemathesis-run.log" 2>&1
SCHEMA_RUN_CODE=$?
set -e
if [[ $SCHEMA_RUN_CODE -eq 0 ]]; then
  record_lane schemathesis-run completed 0 "$REPORT_DIR/logs/schemathesis-run.log"
else
  record_lane schemathesis-run partial "$SCHEMA_RUN_CODE" "$REPORT_DIR/logs/schemathesis-run.log"
fi

set +e
timeout --signal=TERM 300s docker run --rm \
  --network "$NETWORK" \
  -v "$TARGET_DIR/swagger.yml:/app/openapi.yml:ro" \
  -v "$REPORT_DIR/dynamic/schemathesis-fuzz:/app/schemathesis-report:rw" \
  ghcr.io/schemathesis/schemathesis:stable \
  --no-color fuzz /app/openapi.yml \
    --url http://juice-shop-campaign:3000/b2b/v2 \
    --header "Authorization: Bearer $ADMIN_TOKEN" \
    --mode all \
    --max-time 240 \
    --continue-on-failure \
    --report ndjson \
  >"$REPORT_DIR/logs/schemathesis-fuzz.log" 2>&1
SCHEMA_FUZZ_CODE=$?
set -e
if [[ $SCHEMA_FUZZ_CODE -eq 0 ]]; then
  record_lane schemathesis-fuzz completed 0 "$REPORT_DIR/logs/schemathesis-fuzz.log"
else
  record_lane schemathesis-fuzz partial "$SCHEMA_FUZZ_CODE" "$REPORT_DIR/logs/schemathesis-fuzz.log"
fi

set +e
timeout --signal=TERM 900s docker run --rm \
  --network "$NETWORK" \
  -v "$REPORT_DIR/dynamic/zap:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py \
    -t /zap/wrk/openapi.yml \
    -f openapi \
    -I -T 5 \
    -J api-report.json \
    -r api-report.html \
    -w api-report.md \
  >"$REPORT_DIR/logs/zap-api.log" 2>&1
ZAP_API_CODE=$?
set -e
if [[ $ZAP_API_CODE -eq 0 || $ZAP_API_CODE -eq 2 ]]; then
  record_lane zap-api completed "$ZAP_API_CODE" "$REPORT_DIR/logs/zap-api.log"
else
  record_lane zap-api partial "$ZAP_API_CODE" "$REPORT_DIR/logs/zap-api.log"
fi

set +e
timeout --signal=TERM 900s docker run --rm \
  --network "$NETWORK" \
  -v "$REPORT_DIR/dynamic/zap:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py \
    -t http://juice-shop-campaign:3000 \
    -m 2 -I -T 5 \
    -J full-report.json \
    -r full-report.html \
    -w full-report.md \
  >"$REPORT_DIR/logs/zap-full.log" 2>&1
ZAP_FULL_CODE=$?
set -e
if [[ $ZAP_FULL_CODE -eq 0 || $ZAP_FULL_CODE -eq 2 ]]; then
  record_lane zap-full completed "$ZAP_FULL_CODE" "$REPORT_DIR/logs/zap-full.log"
else
  record_lane zap-full partial "$ZAP_FULL_CODE" "$REPORT_DIR/logs/zap-full.log"
fi

normalize_zap_reports
cat "$RUNTIME_PROBE_FINDINGS" "$ZAP_FINDINGS" >"$DYNAMIC_FINDINGS"
if [[ -s "$DYNAMIC_FINDINGS" ]]; then
  run_optional "kuzushi-import-dynamic" \
    "$KUZUSHI_BIN" --target "$TARGET_DIR" run workspace:import-findings \
      --input "$(python3 - "$DYNAMIC_FINDINGS" <<'PY'
import json
import sys
print(json.dumps({"path": sys.argv[1], "tool": "isolated-dynamic-campaign"}))
PY
)"
else
  record_lane kuzushi-import-dynamic skipped 0 "No normalized dynamic findings"
fi

unset ADMIN_TOKEN

afe_put "runtime-probes.json" "$RUNTIME_PROBE_OUTPUT"
afe_put "dynamic-findings.jsonl" "$DYNAMIC_FINDINGS"
afe_checkpoint fuzzing http-openapi \
  "Bounded login/type-confusion probes, Schemathesis, and ZAP ran only against the isolated local container." \
  "campaign:plan $CAMPAIGN_ID" \
  dynamic-analyst

PLAN_INPUT=$(python3 - "$CAMPAIGN_ID" "$KUZUSHI_MODEL" "$MODELS_ROOT" <<'PY'
import json
import sys
print(json.dumps({
    "campaignId": sys.argv[1],
    "tool": "agentic-sast:scan",
    "models": [sys.argv[2]],
    "modelsDir": sys.argv[3],
    "maxJobs": 20,
    "seasonPrompts": True,
    "promptOption": "AGENTIC_SAST_PROMPT",
}))
PY
)
run_required "kuzushi-campaign-plan" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run campaign:plan --input "$PLAN_INPUT"

run_required "prepare-20-independent-jobs" \
  python3 "$KUZUSHI_REPO/.github/scripts/prepare-juice-shop-20x-plan.py" \
    --target-root "$TARGET_DIR" \
    --plan "$PLAN_PATH" \
    --manifest "$INDEPENDENCE_MANIFEST" \
    --model "$KUZUSHI_MODEL"
cp "$PLAN_PATH" "$REPORT_DIR/kuzushi/campaign-plan.json"

afe_put "independence-manifest.json" "$INDEPENDENCE_MANIFEST"
afe_put "campaign-plan.json" "$REPORT_DIR/kuzushi/campaign-plan.json"
afe_checkpoint grading campaign-plan \
  "Exactly 20 unique shard/threat scan jobs were seeded with independent prompt nonces and scope ordering." \
  "kuzushi --target $TARGET_DIR campaign run $CAMPAIGN_ID" \
  campaign-planner

set +e
"$KUZUSHI_BIN" --target "$TARGET_DIR" campaign run "$CAMPAIGN_ID" \
  --workers 3 \
  --max-attempts 2 \
  --job-timeout-secs 2400 \
  --quota-wall-threshold 2 \
  --quota-wall-pause-secs 120 \
  --budget 72 \
  --job-budget 4.25 \
  >"$REPORT_DIR/logs/kuzushi-20x-campaign.log" 2>&1
CAMPAIGN_CODE=$?
set -e
cat "$REPORT_DIR/logs/kuzushi-20x-campaign.log"
if [[ $CAMPAIGN_CODE -eq 0 ]]; then
  record_lane kuzushi-20x-campaign completed 0 "$REPORT_DIR/logs/kuzushi-20x-campaign.log"
else
  record_lane kuzushi-20x-campaign partial "$CAMPAIGN_CODE" "$REPORT_DIR/logs/kuzushi-20x-campaign.log"
fi

run_optional "kuzushi-campaign-status-post-scan" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run campaign:status \
    --input "$(python3 - "$CAMPAIGN_ID" <<'PY'
import json
import sys
print(json.dumps({"campaignId": sys.argv[1]}))
PY
)"
run_optional "kuzushi-campaign-coverage-post-scan" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run campaign:coverage --input '{}'

DEDUPE_INPUT=$(python3 - "$KUZUSHI_MODEL" <<'PY'
import json
import sys
print(json.dumps({
    "maxGroups": 64,
    "maxCandidates": 600,
    "maxEscalations": 16,
    "dryRun": False,
    "model": sys.argv[1],
}))
PY
)
run_optional "kuzushi-triage-dedupe" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run triage:dedupe --input "$DEDUPE_INPUT"

TRIAGE_INPUT=$(python3 - "$KUZUSHI_MODEL" "$TRIAGE_PROMPT_REL" <<'PY'
import json
import sys
print(json.dumps({
    "scope": "all",
    "retriage": True,
    "dedupe": False,
    "votes": 5,
    "strategy": "deep",
    "stage2Tier": "deep",
    "passes": 1,
    "temperature": 0.55,
    "concurrency": 3,
    "costCapUsd": 48,
    "taintTools": "available",
    "TRIAGE_PROMPT": sys.argv[2],
    "model": sys.argv[1],
}))
PY
)
run_optional "kuzushi-five-vote-deep-triage" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run triage:run --input "$TRIAGE_INPUT"

afe_checkpoint reachability triaged-findings \
  "Cross-run dedupe and five-vote deep triage were attempted over the complete canonical findings ledger." \
  "workspace:export-findings post-triage" \
  triage-panel

export_findings_required "export-post-triage-jsonl" "$POST_TRIAGE_REL" jsonl

run_required "select-verification-queues" \
  python3 "$KUZUSHI_REPO/.github/scripts/select-juice-shop-verification.py" \
    --findings "$POST_TRIAGE_FINDINGS" \
    --model-queue "$MODEL_QUEUE" \
    --empirical-queue "$EMPIRICAL_QUEUE" \
    --summary "$VERIFICATION_SELECTION" \
    --max-model 80 \
    --max-empirical 40

MODEL_VERIFY_ATTEMPTED=0
MODEL_VERIFY_COMPLETED=0
while IFS= read -r row; do
  [[ -n "$row" ]] || continue
  MODEL_VERIFY_ATTEMPTED=$((MODEL_VERIFY_ATTEMPTED + 1))
  fp=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["fingerprint"])' "$row")
  severity=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("severity","unknown"))' "$row")
  case "$severity" in
    critical|high) verify_passes=3 ;;
    medium) verify_passes=2 ;;
    *) verify_passes=1 ;;
  esac
  input=$(python3 - "$fp" "$verify_passes" "$VERIFY_PROMPT_REL" "$KUZUSHI_MODEL" <<'PY'
import json
import sys
print(json.dumps({
    "fingerprint": sys.argv[1],
    "VERIFY_PASSES": int(sys.argv[2]),
    "VERIFY_PROMPT": sys.argv[3],
    "mcps": True,
    "mcpToolTimeoutMs": 120000,
    "model": sys.argv[4],
}))
PY
)
  run_optional "verify-model-$(printf '%03d' "$MODEL_VERIFY_ATTEMPTED")" \
    "$KUZUSHI_BIN" --target "$TARGET_DIR" run verify:finding --input "$input"
  if [[ $LAST_EXIT_CODE -eq 0 ]]; then
    MODEL_VERIFY_COMPLETED=$((MODEL_VERIFY_COMPLETED + 1))
  fi
done <"$MODEL_QUEUE"

EMPIRICAL_VERIFY_ATTEMPTED=0
EMPIRICAL_VERIFY_COMPLETED=0
while IFS= read -r row; do
  [[ -n "$row" ]] || continue
  EMPIRICAL_VERIFY_ATTEMPTED=$((EMPIRICAL_VERIFY_ATTEMPTED + 1))
  fp=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["fingerprint"])' "$row")
  input=$(python3 - "$fp" <<'PY'
import json
import sys
print(json.dumps({"fingerprint": sys.argv[1]}))
PY
)
  run_optional "verify-empirical-$(printf '%03d' "$EMPIRICAL_VERIFY_ATTEMPTED")" \
    "$KUZUSHI_BIN" --target "$TARGET_DIR" run verify:exploit --input "$input"
  if [[ $LAST_EXIT_CODE -eq 0 ]]; then
    EMPIRICAL_VERIFY_COMPLETED=$((EMPIRICAL_VERIFY_COMPLETED + 1))
  fi
done <"$EMPIRICAL_QUEUE"

afe_checkpoint dedupe findings-ledger \
  "Canonical identity dedupe, triage verdicts, independent verification panels, and empirical outcomes are preserved separately." \
  "workspace:export-findings final" \
  evidence-correlator
afe_checkpoint patch no-source-mutation \
  "Auto-patching remained disabled and the tracked Juice Shop source tree was not modified." \
  "workspace:export-findings final" \
  patch-governor

export_findings_required "export-final-jsonl" "$FINAL_FINDINGS_REL" jsonl
export_findings_optional "export-final-sarif" "$KUZUSHI_EXPORT_REL/findings.sarif" sarif
export_findings_optional "export-final-json" "$KUZUSHI_EXPORT_REL/findings.json" json
export_findings_optional "export-final-markdown" "$KUZUSHI_EXPORT_REL/markdown" markdown-bundle

run_optional "kuzushi-campaign-status-final" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run campaign:status \
    --input "$(python3 - "$CAMPAIGN_ID" <<'PY'
import json
import sys
print(json.dumps({"campaignId": sys.argv[1]}))
PY
)"
run_optional "kuzushi-campaign-coverage-final" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run campaign:coverage --input '{}'
run_optional "kuzushi-runs-list" \
  "$KUZUSHI_BIN" runs list --target "$TARGET_DIR" --json

afe_put "post-triage-findings.jsonl" "$POST_TRIAGE_FINDINGS"
afe_put "final-findings.jsonl" "$FINAL_FINDINGS"
afe_put "verification-selection.json" "$VERIFICATION_SELECTION"
run_optional "afe-campaign-phase-audit" \
  "$AFE_BIN" --data-root "$AFE_DATA" campaign-phase-audit "$AFE_RUN_ID"
run_optional "afe-campaign-report" \
  "$AFE_BIN" --data-root "$AFE_DATA" campaign-report "$AFE_RUN_ID" \
    --project juice-shop --artifact-prefix juice-shop-20x
afe_checkpoint report campaign-bundle \
  "Kuzushi exports, AFE checkpoint ledger, CPG digests, DAST receipts, triage, and verification evidence were assembled." \
  "export-bundle-create $AFE_RUN_ID" \
  report-builder
run_optional "afe-export-bundle" \
  "$AFE_BIN" --data-root "$AFE_DATA" export-bundle-create "$AFE_RUN_ID" \
    --project juice-shop --artifact-name juice-shop-20x
run_optional "afe-campaign-completion" \
  "$AFE_BIN" --data-root "$AFE_DATA" campaign-completion-audit "$AFE_RUN_ID" \
    --project juice-shop --no-require-report
afe_checkpoint export github-actions-artifact \
  "Sanitized campaign output is ready for artifact publication; OAuth credentials and local application tokens are excluded." \
  "upload-artifact juice-shop-20x" \
  artifact-manager

run_required "verify-no-tracked-source-mutation" bash -c '
  test -z "$(git -C "$TARGET_DIR" status --porcelain --untracked-files=no)"
  changed=$(git -C "$TARGET_DIR" diff --name-only "$TARGET_BASE_SHA" "$TARGET_SHA")
  test "$changed" = "routes/login.ts"
'

copy_kuzushi_evidence

python3 - "$REPORT_DIR" "$FINAL_FINDINGS" "$INDEPENDENCE_MANIFEST" "$VERIFICATION_SELECTION" \
  "$CAMPAIGN_ID" "$AFE_RUN_ID" "$MODEL_VERIFY_ATTEMPTED" "$MODEL_VERIFY_COMPLETED" \
  "$EMPIRICAL_VERIFY_ATTEMPTED" "$EMPIRICAL_VERIFY_COMPLETED" <<'PY'
import json
import pathlib
import sys

(
    root_raw,
    findings_raw,
    independence_raw,
    selection_raw,
    campaign_id,
    afe_run_id,
    model_attempted,
    model_completed,
    empirical_attempted,
    empirical_completed,
) = sys.argv[1:]
root = pathlib.Path(root_raw)
findings_path = pathlib.Path(findings_raw)
independence = json.loads(pathlib.Path(independence_raw).read_text(encoding="utf-8"))
selection = json.loads(pathlib.Path(selection_raw).read_text(encoding="utf-8"))
lanes = []
status_path = root / "lane-status.jsonl"
if status_path.is_file():
    for line in status_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            lanes.append(json.loads(line))
findings = []
if findings_path.is_file():
    for line in findings_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            findings.append(json.loads(line))
        except Exception:
            pass
severity_counts = {}
for finding in findings:
    severity = str(finding.get("severity") or "unknown").lower()
    severity_counts[severity] = severity_counts.get(severity, 0) + 1

summary = {
    "schemaVersion": 1,
    "campaignId": campaign_id,
    "afeRunId": afe_run_id,
    "requestedIndependentScans": 20,
    "preparedIndependentScans": independence.get("jobCount"),
    "independenceMethod": independence.get("independenceMethod"),
    "findingCount": len(findings),
    "findingSeverities": severity_counts,
    "verificationSelection": selection,
    "modelVerification": {
        "attempted": int(model_attempted),
        "completedCommands": int(model_completed),
        "note": "Command completion does not itself mean the finding was confirmed exploitable; inspect each persisted verification verdict.",
    },
    "empiricalVerification": {
        "attempted": int(empirical_attempted),
        "completedCommands": int(empirical_completed),
        "note": "Unsupported or not-reproduced outcomes remain valid empirical receipts and must not be rewritten as successful exploitation.",
    },
    "laneCounts": {
        status: sum(1 for lane in lanes if lane.get("status") == status)
        for status in ("completed", "partial", "failed", "skipped")
    },
    "proofPolicy": {
        "modelOutputAdvisory": True,
        "runtimeAndDeterministicReceiptsAuthoritative": True,
        "sourceMutationAllowed": False,
        "findingCountIsNotConfirmedVulnerabilityCount": True,
    },
    "lanes": lanes,
}
(root / "campaign-summary.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

record_lane campaign-bundle completed 0 "$REPORT_DIR/campaign-summary.json"
find "$REPORT_DIR" -type f ! -name SHA256SUMS -print0 \
  | sort -z \
  | xargs -0 sha256sum >"$REPORT_DIR/SHA256SUMS"

echo "Juice Shop 20× campaign finished: $REPORT_DIR"
