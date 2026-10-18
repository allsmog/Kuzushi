"""Native session cost recovery with one fully intercepted context request."""
import hashlib
import json
import shutil
import sqlite3
import sys
from pathlib import Path

import context_question
from map_functionality import execute


def seed(root, evidence, home):
    context_question.seed(root, evidence, home)
    shutil.copyfile(Path(__file__).with_name("cost_recovery_provider.mjs"),
                    evidence / "context-question-provider.mjs")
    config = home / ".kuzushi/v3/config.toml"
    with config.open("a") as stream:
        stream.write("\n[operator]\nsession_budget_usd = 1.0\n")
    value = {"threatModelRef": json.loads((evidence / "map-ref.json").read_text()),
        "question": "Explain this labeled static context without source execution.", "maxOutputTokens": 256}
    campaign = "owned-cost-question"
    draft = execute(root, evidence, home, "cost-draft", "campaign:context-study", {
        "campaignId": campaign, "investigationId": "owned-cost-recovery",
        "generationTool": "threat-model:ask", "contextInput": value})
    execute(root, evidence, home, "cost-approval", "campaign:approve-allowance", {
        "investigationId": "owned-cost-recovery", "expectedRevision": 0,
        "model": "openai-codex:gpt-5.5", "maxProviderCalls": 2, "protectedReviewCalls": 1,
        "campaignId": campaign, "campaignPlanSha256": draft["planSha256"],
        "campaignJobs": 1, "maxJobAttempts": 1,
        "reason": "One intercepted owned context question, no live provider calls"})
    plan = json.loads((root / ".kuzushi/v3/campaigns" / campaign / "plan.json").read_text())
    value = plan["jobs"][0]["input"]
    value["allowanceRef"] = {"schemaVersion": 1,
        "investigationId": "owned-cost-recovery", "revision": 1, "workId": campaign + ":context-001"}
    (evidence / "cost-request.txt").write_text("run threat-model:ask " + json.dumps(value))


def verify(root, evidence):
    assert hashlib.sha256((root / "app.py").read_bytes()).hexdigest() == (evidence / "source-before.sha256").read_text()
    assert hashlib.sha256((root / ".kuzushi/threat-models/manifest.json").read_bytes()).hexdigest() == json.loads((evidence / "context-manifest-before.json").read_text())["sha256"]
    calls = (evidence / "synthetic-provider-calls.jsonl").read_text().splitlines()
    assert len(calls) == 1
    assert json.loads(calls[0])["liveProviderCalls"] == 0
    answers = [path for path in (root / ".kuzushi/v3/runs").glob("*/result.json")
               if json.loads(path.read_text()).get("data", {}).get("answer")]
    assert len(answers) == 1
    (evidence / "cost-replay.txt").write_text("replay " + answers[0].parent.name)
    db_path = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(db_path.as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 1
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 0
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions where investigation_id = 'owned-cost-recovery'").fetchone()[0])
        assert approval["limits"] == {"maxProviderCalls": 2, "protectedReviewCalls": 1}
    report_hash = verify_export(root)
    (evidence / "verified.json").write_text(json.dumps({"syntheticProviderCalls": 1,
        "liveProviderCalls": 0, "sourceUnchanged": True, "sourceExecuted": False,
        "findingObservations": 0, "providerReservations": 1,
        "reportSha256": report_hash, "reportResults": 0}, indent=2) + "\n")


def verify_export(root):
    path = root / ".kuzushi/reports/report.sarif"
    report = json.loads(path.read_text())
    assert report["version"] == "2.1.0" and len(report["runs"]) == 1
    assert report["runs"][0]["results"] == []
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_pages(evidence):
    first = next(evidence.glob("*-cost-40x12.txt")).read_text()
    pages = [next(evidence.glob(f"*-cost-page-{index}-40x12.txt")).read_text()
             for index in range(1, 4)]
    assert first != pages[0], "Page Down must move the Cost reader"
    assert len(set(pages)) == 3, "Each compact page must advance"
    text = "\n".join(pages)
    assert "incomplete)" in text and "unknown" in text
    assert "PgUp/PgDn" in text
    assert "100%" not in text


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    evidence.mkdir(parents=True, exist_ok=True)
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif sys.argv[3] == "check-pages":
        check_pages(evidence)
    else:
        verify(root, evidence)
