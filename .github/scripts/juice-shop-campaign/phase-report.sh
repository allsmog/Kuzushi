run_optional "afe-campaign-phase-audit" \
  "$AFE_BIN" --data-root "$AFE_DATA" campaign-phase-audit "$AFE_RUN_ID"
run_optional "afe-campaign-report" \
  "$AFE_BIN" --data-root "$AFE_DATA" campaign-report "$AFE_RUN_ID" \
    --project juice-shop --artifact-prefix deep-campaign

afe_checkpoint report campaign-bundle \
  "Threat model, exact 20-cell plan, source lineage, CPG digests, static and dynamic receipts, triage decisions, verification attempts, and final exports were assembled into one campaign artifact." \
  "export-bundle-create $AFE_RUN_ID" \
  report-builder
run_optional "afe-export-bundle" \
  "$AFE_BIN" --data-root "$AFE_DATA" export-bundle-create "$AFE_RUN_ID" \
    --project juice-shop --artifact-name juice-shop-20x-deep-campaign
run_optional "afe-campaign-completion" \
  "$AFE_BIN" --data-root "$AFE_DATA" campaign-completion-audit "$AFE_RUN_ID" \
    --project juice-shop --no-require-report

afe_checkpoint export github-actions-artifact \
  "Sanitized campaign output is ready for GitHub Actions artifact publication; OAuth credentials, private download URLs, and local application tokens are excluded." \
  "upload-artifact juice-shop-20x-deep-campaign" \
  artifact-manager

run_required "verify-no-source-mutation" python3 - "$TARGET_DIR" <<'PY'
import pathlib
import subprocess
import sys

target = pathlib.Path(sys.argv[1])
status = subprocess.check_output(
    ["git", "-C", str(target), "status", "--porcelain=v1", "--untracked-files=all"],
    text=True,
)
unexpected = []
for line in status.splitlines():
    path = line[3:].split(" -> ")[-1]
    if path == ".kuzushi" or path.startswith(".kuzushi/"):
        continue
    unexpected.append(line)
if unexpected:
    raise SystemExit("source tree mutated outside .kuzushi:\n" + "\n".join(unexpected))
PY

run_required "summarize-campaign" python3 "$CAMPAIGN_TOOLS" summary \
  --report-root "$REPORT_DIR" \
  --findings "$KUZUSHI_REPORT_ROOT/findings.jsonl" \
  --plan "$PLAN_PATH" \
  --queue "$QUEUE_PATH" \
  --candidates "$VERIFY_CANDIDATES"
record_lane campaign-bundle completed 0 "$REPORT_DIR/campaign-summary.json"

find "$REPORT_DIR" -type f ! -name SHA256SUMS -print0 \
  | sort -z \
  | xargs -0 sha256sum >"$REPORT_DIR/SHA256SUMS"

echo "Juice Shop 20-scan campaign complete: $REPORT_DIR"
