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

ADMIN_TOKEN=$(curl --silent --show-error \
  -H 'content-type: application/json' \
  --data '{"email":"admin@juice-sh.op","password":"admin123"}' \
  http://127.0.0.1:3000/rest/user/login 2>/dev/null \
  | python3 -c 'import json,sys
try:
 print(json.load(sys.stdin).get("authentication", {}).get("token", ""))
except Exception:
 print("")' || true)

cp "$TARGET_DIR/swagger.yml" "$REPORT_DIR/dynamic/zap/openapi.yml"
sed -i 's#url: /b2b/v2#url: http://juice-shop-campaign:3000/b2b/v2#' \
  "$REPORT_DIR/dynamic/zap/openapi.yml"

SCHEMA_AUTH_ARGS=()
if [[ -n "$ADMIN_TOKEN" ]]; then
  SCHEMA_AUTH_ARGS=(--header "Authorization: Bearer $ADMIN_TOKEN")
  record_lane dynamic-auth completed 0 "local admin token acquired for authenticated schema testing"
else
  record_lane dynamic-auth partial 0 "authenticated schema token unavailable; unauthenticated behavior still tested"
fi

set +e
timeout --signal=TERM 900s docker run --rm \
  --network "$NETWORK" \
  -v "$TARGET_DIR/swagger.yml:/app/openapi.yml:ro" \
  -v "$REPORT_DIR/dynamic/schemathesis-run:/app/schemathesis-report:rw" \
  -e SCHEMATHESIS_COVERAGE_REPORT_HTML_PATH=/app/schemathesis-report/schema-coverage.html \
  ghcr.io/schemathesis/schemathesis:stable \
  --no-color run -w 4 /app/openapi.yml \
    --url http://juice-shop-campaign:3000/b2b/v2 \
    "${SCHEMA_AUTH_ARGS[@]}" \
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
    "${SCHEMA_AUTH_ARGS[@]}" \
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

run_required "bounded-http-fuzz" python3 "$CAMPAIGN_TOOLS" http-fuzz \
  --base http://127.0.0.1:3000 \
  --results "$REPORT_DIR/dynamic/http-fuzz.json" \
  --findings "$REPORT_DIR/dynamic/http-fuzz-findings.jsonl"
run_required "normalize-zap" python3 "$CAMPAIGN_TOOLS" normalize-zap \
  --root "$REPORT_DIR/dynamic/zap" \
  --out "$REPORT_DIR/dynamic/zap-findings.jsonl"

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
  "Schemathesis, ZAP API/full scans, and custom bounded HTTP mutation ran only against the isolated local container; raw and normalized receipts were retained." \
  "campaign:plan $CAMPAIGN_ID" \
  dynamic-analyst
