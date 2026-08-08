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

CAMPAIGN_ID="juice-shop-deep-${GITHUB_RUN_ID:-local}"
AFE_RUN_ID="afe-${CAMPAIGN_ID}"
AFE_DATA="$REPORT_DIR/afe-state"
APP_IMAGE="juice-shop-deep:${GITHUB_RUN_ID:-local}"
APP_CONTAINER="juice-shop-deep-${GITHUB_RUN_ID:-local}"
NETWORK="juice-shop-deep-${GITHUB_RUN_ID:-local}"
LANE_STATUS="$REPORT_DIR/lane-status.jsonl"
KUZUSHI_REPORT_ROOT="$TARGET_DIR/.kuzushi/v3/reports/deep-campaign"

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

cat >"$REPORT_DIR/README.md" <<EOF
# Juice Shop deep Kuzushi campaign

- Target: allsmog/juice-shop PR #1 at \`$TARGET_SHA\`
- Baseline: \`$TARGET_BASE_SHA\`
- Model: \`$KUZUSHI_MODEL\`
- Kuzushi: \`$(git -C "$KUZUSHI_REPO" rev-parse HEAD)\`
- Agentic Fuzz Engine: \`$AFE_SHA\`
- Oxidized Joern checkout: \`$OXIDIZED_SHA\`
- Scope: local Docker target only; no public Juice Shop instance is contacted.
- Mutation policy: no auto-patching. Scanner/model outputs are evidence candidates, not source changes.
- Budget policy: one one-token auth preflight, then a hard \`$16\` model campaign ceiling; \`$3.50\` graceful tool budget and \`$4.50\` hard backstop per job.
- Proof policy: runtime receipts and deterministic CPG/scanner artifacts are authoritative; model assessments remain advisory.
EOF

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
  "githubRunId": os.environ.get("GITHUB_RUN_ID"),
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(out, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

run_required "verify-target-lineage" bash -c '
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
  "Kuzushi context, entry-point extraction, and deterministic shard proposal completed or emitted explicit partial receipts." \
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
  "TypeScript and JavaScript CPG artifacts built through the checked-out Oxidized Joern-backed Kuzushi engine; artifact digests recorded." \
  "kuzushi --target $TARGET_DIR run secret-scan:scan" \
  cpg-builder

run_required "kuzushi-secret-scan" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run secret-scan:scan --input '{}'
run_optional "kuzushi-semgrep" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run semgrep:scan --input '{"config":"p/owasp-top-ten"}'

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
timeout --signal=TERM 900s docker run --rm \
  --network "$NETWORK" \
  -v "$TARGET_DIR/swagger.yml:/app/openapi.yml:ro" \
  -v "$REPORT_DIR/dynamic/schemathesis-run:/app/schemathesis-report:rw" \
  -e SCHEMATHESIS_COVERAGE_REPORT_HTML_PATH=/app/schemathesis-report/schema-coverage.html \
  ghcr.io/schemathesis/schemathesis:stable \
  --no-color run -w 4 /app/openapi.yml \
    --url http://juice-shop-campaign:3000/b2b/v2 \
    --header "Authorization: Bearer $ADMIN_TOKEN" \
    --mode all \
    --max-examples 250 \
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
timeout --signal=TERM 1200s docker run --rm \
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
timeout --signal=TERM 1200s docker run --rm \
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

python3 - "$REPORT_DIR/dynamic/http-fuzz.json" "$REPORT_DIR/dynamic/http-fuzz-findings.jsonl" <<'PY'
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

results_path, findings_path = sys.argv[1:]
base = "http://127.0.0.1:3000"
wrong_password = "definitely-not-the-password"
email_payloads = [
    "admin@juice-sh.op'-- ",
    "jim@juice-sh.op'-- ",
    "bender@juice-sh.op'-- ",
    "chris.pike@juice-sh.op'-- ",
    "' OR 1=1-- ",
    '" OR "1"="1',
    "admin@juice-sh.op\\u0000'-- ",
    "💥@juice-sh.op",
    "A" * 4096,
]
body_payloads = [
    {"email": None, "password": wrong_password},
    {"email": [], "password": wrong_password},
    {"email": {}, "password": wrong_password},
    {"email": "admin@juice-sh.op", "password": None},
    {"email": "admin@juice-sh.op", "password": []},
    {"email": "admin@juice-sh.op", "password": {}},
]
search_payloads = [
    "'", '"', "%' OR 1=1--", "../" * 20, "${7*7}", "<script>alert(1)</script>", "A" * 4096,
]
rows = []
findings = []

def request(method, url, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("content-type", "application/json")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            raw = response.read(1_000_000)
            status = response.status
    except urllib.error.HTTPError as error:
        status = error.code
        raw = error.read(1_000_000)
    except Exception as error:
        return {"status": None, "error": type(error).__name__, "durationMs": int((time.monotonic()-started)*1000)}
    parsed = None
    try:
        parsed = json.loads(raw)
    except Exception:
        pass
    return {
        "status": status,
        "durationMs": int((time.monotonic()-started)*1000),
        "bytes": len(raw),
        "bodySha256": hashlib.sha256(raw).hexdigest(),
        "authenticated": bool(isinstance(parsed, dict) and parsed.get("authentication")),
    }

for payload in email_payloads:
    result = request("POST", f"{base}/rest/user/login", {"email": payload, "password": wrong_password})
    row = {"surface": "login", "case": "email-string", "payloadSha256": hashlib.sha256(payload.encode()).hexdigest(), **result}
    rows.append(row)
    if result.get("authenticated") or (result.get("status") or 0) >= 500 or result.get("status") is None:
        findings.append({
            "file": "runtime/rest-user-login",
            "line": 1,
            "title": "HTTP fuzz anomaly on POST /rest/user/login",
            "severity": "high" if result.get("authenticated") else "medium",
            "class": "dynamic-http-fuzz",
            "cwe": "CWE-89" if result.get("authenticated") else "CWE-20",
        })

for body in body_payloads:
    encoded = json.dumps(body, sort_keys=True, default=str)
    result = request("POST", f"{base}/rest/user/login", body)
    rows.append({"surface": "login", "case": "type-confusion", "payloadSha256": hashlib.sha256(encoded.encode()).hexdigest(), **result})
    if result.get("authenticated") or (result.get("status") or 0) >= 500 or result.get("status") is None:
        findings.append({
            "file": "runtime/rest-user-login",
            "line": 1,
            "title": "Type-confusion anomaly on POST /rest/user/login",
            "severity": "high" if result.get("authenticated") else "medium",
            "class": "dynamic-http-fuzz",
            "cwe": "CWE-20",
        })

for payload in search_payloads:
    result = request("GET", f"{base}/rest/products/search?q={urllib.parse.quote(payload)}")
    rows.append({"surface": "product-search", "case": "query", "payloadSha256": hashlib.sha256(payload.encode()).hexdigest(), **result})
    if (result.get("status") or 0) >= 500 or result.get("status") is None:
        findings.append({
            "file": "runtime/rest-products-search",
            "line": 1,
            "title": "HTTP fuzz anomaly on GET /rest/products/search",
            "severity": "medium",
            "class": "dynamic-http-fuzz",
            "cwe": "CWE-20",
        })

with open(results_path, "w", encoding="utf-8") as handle:
    json.dump({"cases": rows, "anomalyCount": len(findings)}, handle, indent=2, sort_keys=True)
    handle.write("\n")
with open(findings_path, "w", encoding="utf-8") as handle:
    seen = set()
    for finding in findings:
        key = tuple(sorted(finding.items()))
        if key in seen:
            continue
        seen.add(key)
        handle.write(json.dumps(finding, sort_keys=True) + "\n")
PY
record_lane http-fuzz completed 0 "$REPORT_DIR/dynamic/http-fuzz.json"

python3 - "$REPORT_DIR/dynamic/zap" "$REPORT_DIR/dynamic/zap-findings.jsonl" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
risk_map = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
rows = []
for report in (root / "api-report.json", root / "full-report.json"):
    if not report.exists():
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
                rows.append({
                    "file": "runtime/" + uri.replace("://", "/").lstrip("/")[:300],
                    "line": 1,
                    "title": f"ZAP: {alert.get('alert') or alert.get('name') or 'HTTP security alert'}",
                    "severity": risk_map.get(str(alert.get("riskdesc", "")).split(" ")[0], "info"),
                    "class": "dynamic-zap",
                    **({"cwe": f"CWE-{cwe}"} if cwe and cwe != "-1" else {}),
                })
with out.open("w", encoding="utf-8") as handle:
    seen = set()
    for row in rows:
        key = (row["file"], row["title"], row.get("cwe"))
        if key in seen:
            continue
        seen.add(key)
        handle.write(json.dumps(row, sort_keys=True) + "\n")
PY

cat "$REPORT_DIR/dynamic/zap-findings.jsonl" \
    "$REPORT_DIR/dynamic/http-fuzz-findings.jsonl" \
    >"$REPORT_DIR/dynamic/dynamic-findings.jsonl"

if [[ -s "$REPORT_DIR/dynamic/dynamic-findings.jsonl" ]]; then
  run_optional "kuzushi-import-dynamic" \
    "$KUZUSHI_BIN" --target "$TARGET_DIR" run workspace:import-findings \
      --input "{\"path\":\"$REPORT_DIR/dynamic/dynamic-findings.jsonl\",\"tool\":\"isolated-dynamic-campaign\"}"
else
  record_lane kuzushi-import-dynamic skipped 0 "No normalized dynamic findings"
fi

afe_put "http-fuzz.json" "$REPORT_DIR/dynamic/http-fuzz.json"
afe_put "dynamic-findings.jsonl" "$REPORT_DIR/dynamic/dynamic-findings.jsonl"
afe_checkpoint fuzzing http-openapi \
  "Schemathesis, ZAP API/full scans, and bounded custom HTTP mutation ran only against the isolated local container; raw and normalized receipts captured." \
  "campaign-plan $CAMPAIGN_ID" \
  dynamic-analyst

docker rm --force "$APP_CONTAINER" >/dev/null 2>&1 || true
docker network rm "$NETWORK" >/dev/null 2>&1 || true

mkdir -p "$TARGET_DIR/.kuzushi/v3/campaign-models"
cat >"$TARGET_DIR/.kuzushi/shards.toml" <<'EOF'
[shards.authentication]
paths = [
  "routes/login.ts",
  "routes/2fa.ts",
  "routes/changePassword.ts",
  "routes/resetPassword.ts",
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
]

[shards.data-models]
paths = ["data", "models", "lib"]

[shards.frontend-trust]
paths = ["frontend/src/app"]
EOF

cat >"$TARGET_DIR/.kuzushi/v3/campaign-models/http-trust-boundaries.json" <<'EOF'
{
  "threats": [
    {
      "id": "untrusted-http-to-sensitive-sink",
      "title": "Untrusted HTTP input reaches authentication, data, filesystem, rendering, or outbound-request sinks",
      "description": "Prioritize source-to-sink paths across request bodies, route/query parameters, authorization state, ORM/raw SQL, filesystem access, redirects, template/HTML rendering, deserialization, and outbound network calls. Dynamic scanner evidence is untrusted input and must be corroborated against source or runtime receipts.",
      "severity": "high",
      "relatedCwe": ["CWE-20", "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-918", "CWE-639"]
    }
  ]
}
EOF

PLAN_INPUT=$(python3 - <<PY
import json
print(json.dumps({
  "campaignId": "$CAMPAIGN_ID",
  "tool": "agentic-sast:scan",
  "models": ["$KUZUSHI_MODEL"],
  "modelsDir": "$TARGET_DIR/.kuzushi/v3/campaign-models",
  "maxJobs": 4,
  "seasonPrompts": True,
  "promptOption": "AGENTIC_SAST_PROMPT",
}))
PY
)
run_required "kuzushi-campaign-plan" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run campaign:plan --input "$PLAN_INPUT"

PLAN_PATH="$TARGET_DIR/.kuzushi/v3/campaigns/$CAMPAIGN_ID/plan.json"
python3 - "$PLAN_PATH" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    plan = json.load(handle)
for job in plan.get("jobs", []):
    input_data = job.setdefault("input", {})
    input_data.update({
        "strategy": "chunked",
        "language": "unknown",
        "maxTokensPerChunk": 10000,
        "depositUsdPerChunk": 1.25,
        "budgetUsd": 3.5,
        "autoTriage": True,
        "autoTriageMaxSteps": 8,
        "autoTriageDepositUsd": 0.75,
        "maxFindings": 25,
        "passes": 1,
    })
    job["jobBudgetUsd"] = 4.0
with open(path, "w", encoding="utf-8") as handle:
    json.dump(plan, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
cp "$PLAN_PATH" "$REPORT_DIR/kuzushi/campaign-plan.json"

afe_checkpoint grading campaign-plan \
  "Four threat-seasoned Monorepo jobs planned with explicit per-tool and per-job budgets; no silent model fallback and no auto-patching." \
  "kuzushi --target $TARGET_DIR campaign run $CAMPAIGN_ID" \
  campaign-planner

set +e
"$KUZUSHI_BIN" --target "$TARGET_DIR" campaign run "$CAMPAIGN_ID" \
  --workers 2 \
  --max-attempts 1 \
  --job-timeout-secs 1800 \
  --quota-wall-threshold 2 \
  --quota-wall-pause-secs 120 \
  --budget 16 \
  --job-budget 4.5 \
  >"$REPORT_DIR/logs/kuzushi-campaign-run.log" 2>&1
CAMPAIGN_CODE=$?
set -e
cat "$REPORT_DIR/logs/kuzushi-campaign-run.log"
if [[ $CAMPAIGN_CODE -eq 0 ]]; then
  record_lane kuzushi-campaign completed 0 "$REPORT_DIR/logs/kuzushi-campaign-run.log"
else
  record_lane kuzushi-campaign partial "$CAMPAIGN_CODE" "$REPORT_DIR/logs/kuzushi-campaign-run.log"
fi

run_optional "kuzushi-campaign-status" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run campaign:status \
    --input "{\"campaignId\":\"$CAMPAIGN_ID\"}"
run_optional "kuzushi-campaign-coverage" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run campaign:coverage --input '{}'
run_optional "kuzushi-runs-list" \
  "$KUZUSHI_BIN" runs list --target "$TARGET_DIR" --json

run_optional "kuzushi-export-jsonl" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run workspace:export-findings \
    --input '{"output":".kuzushi/v3/reports/deep-campaign/findings.jsonl","format":"jsonl","completeness":"all","allowEmpty":true}'
run_optional "kuzushi-export-sarif" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run workspace:export-findings \
    --input '{"output":".kuzushi/v3/reports/deep-campaign/findings.sarif","format":"sarif","completeness":"all","allowEmpty":true}'
run_optional "kuzushi-export-markdown" \
  "$KUZUSHI_BIN" --target "$TARGET_DIR" run workspace:export-findings \
    --input '{"output":".kuzushi/v3/reports/deep-campaign/markdown","format":"markdown-bundle","completeness":"all","allowEmpty":true}'

cp -R "$KUZUSHI_REPORT_ROOT" "$REPORT_DIR/kuzushi/export" 2>/dev/null || true
cp -R "$TARGET_DIR/.kuzushi/v3/campaigns/$CAMPAIGN_ID" "$REPORT_DIR/kuzushi/campaign" 2>/dev/null || true
cp -R "$TARGET_DIR/.kuzushi/v3/runs" "$REPORT_DIR/kuzushi/runs" 2>/dev/null || true

FINDINGS_JSONL="$KUZUSHI_REPORT_ROOT/findings.jsonl"
afe_put "kuzushi-findings.jsonl" "$FINDINGS_JSONL"
afe_put "kuzushi-findings.sarif" "$KUZUSHI_REPORT_ROOT/findings.sarif"
afe_put "kuzushi-campaign-plan.json" "$PLAN_PATH"
afe_checkpoint reachability source-runtime-corroboration \
  "CPG-backed and chunked Monorepo findings coexist with dynamic runtime evidence; proof states remain separate in Kuzushi artifacts." \
  "workspace:export-findings" \
  evidence-correlator

afe_checkpoint dedupe findings-ledger \
  "Kuzushi canonical findings ledger and campaign coverage fold preserve cross-tool identities; raw dynamic receipts remain available for independent review." \
  "campaign-report $AFE_RUN_ID" \
  dedupe-reviewer

afe_checkpoint patch no-source-mutation \
  "Auto-patching was disabled. The campaign evaluated the existing PR commit without modifying source; re-verification receipts are retained separately." \
  "campaign-report $AFE_RUN_ID" \
  patch-governor

run_optional "afe-campaign-phase-audit" \
  "$AFE_BIN" --data-root "$AFE_DATA" campaign-phase-audit "$AFE_RUN_ID"
run_optional "afe-campaign-report" \
  "$AFE_BIN" --data-root "$AFE_DATA" campaign-report "$AFE_RUN_ID" \
    --project juice-shop --artifact-prefix deep-campaign

afe_checkpoint report campaign-bundle \
  "Kuzushi exports, AFE checkpoint ledger, CPG digests, scanner logs, and DAST reports assembled into one bounded campaign artifact." \
  "export-bundle-create $AFE_RUN_ID" \
  report-builder
run_optional "afe-export-bundle" \
  "$AFE_BIN" --data-root "$AFE_DATA" export-bundle-create "$AFE_RUN_ID" \
    --project juice-shop --artifact-name juice-shop-deep-campaign
run_optional "afe-campaign-completion" \
  "$AFE_BIN" --data-root "$AFE_DATA" campaign-completion-audit "$AFE_RUN_ID" \
    --project juice-shop --no-require-report

afe_checkpoint export github-actions-artifact \
  "Sanitized campaign output is ready for GitHub Actions artifact publication; OAuth credentials and local app tokens are excluded." \
  "upload-artifact juice-shop-deep-campaign" \
  artifact-manager

python3 - "$REPORT_DIR" "$FINDINGS_JSONL" "$CAMPAIGN_ID" "$AFE_RUN_ID" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
findings_path = pathlib.Path(sys.argv[2])
campaign_id = sys.argv[3]
afe_run_id = sys.argv[4]
lanes = []
status_file = root / "lane-status.jsonl"
if status_file.exists():
    for line in status_file.read_text(encoding="utf-8").splitlines():
        if line.strip():
            lanes.append(json.loads(line))
findings = []
if findings_path.exists():
    for line in findings_path.read_text(encoding="utf-8").splitlines():
        try:
            findings.append(json.loads(line))
        except Exception:
            pass
summary = {
    "campaignId": campaign_id,
    "afeRunId": afe_run_id,
    "laneCounts": {
        status: sum(1 for lane in lanes if lane.get("status") == status)
        for status in ("completed", "partial", "failed", "skipped")
    },
    "findingCount": len(findings),
    "findingSeverities": {},
    "findingStateCaveat": "Export includes scanner candidates, model judgments, imported runtime observations, and human decisions as distinct fields; count is not a confirmed-vulnerability count.",
    "proofPolicy": {
        "deterministicAndRuntimeEvidenceAuthoritative": True,
        "modelOutputAdvisory": True,
        "autoPatch": False,
    },
    "lanes": lanes,
}
for finding in findings:
    severity = str(finding.get("severity") or "unknown").lower()
    summary["findingSeverities"][severity] = summary["findingSeverities"].get(severity, 0) + 1
(root / "campaign-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

record_lane campaign-bundle completed 0 "$REPORT_DIR/campaign-summary.json"
find "$REPORT_DIR" -type f ! -name SHA256SUMS -print0 \
  | sort -z \
  | xargs -0 sha256sum >"$REPORT_DIR/SHA256SUMS"

echo "Deep campaign complete: $REPORT_DIR"
