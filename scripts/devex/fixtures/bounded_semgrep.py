"""Installed Semgrep over harmless owned policy text. Never execute source."""
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

from secret_settings import ledger


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source_hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["service/notice.py", "loose.py"]}


def seed(root, evidence, home):
    binary = shutil.which("semgrep")
    assert binary, "Installed Semgrep is required"
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "service").mkdir(exist_ok=True)
    (root / "service/notice.py").write_text('# Owned inert policy fixture. Never executed.\nprint("OWNER_POLICY_REVIEW")\n')
    (root / "loose.py").write_text('# Owned inert root file. Never executed.\nprint("ordinary notice")\n')
    rules = evidence / "local-rules.yaml"
    rules.write_text('rules:\n  - id: owned-policy-marker\n    languages: [python]\n    severity: INFO\n    message: Owned policy marker needs an owner decision\n    pattern: print("OWNER_POLICY_REVIEW")\n')
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    document = {"version":"1", "methodology":"stride", "title":"Owned source policy context",
        "systemContext":"Two owned Python text fixtures contain print syntax. service/notice.py holds an owner-policy marker; loose.py holds an ordinary notice. Source is read only. No application, vulnerability, execution or runtime data flow is established.",
        "dfd":{"nodes":[{"id":"policy-text","name":"Policy text","type":"data-store","trustZone":"repository",
            "description":"service/notice.py contains the OWNER_POLICY_REVIEW literal.","purpose":"Supplies a harmless local-rule observation for owner review."},
            {"id":"root-text","name":"Root source text","type":"data-store","trustZone":"repository",
             "description":"loose.py contains an ordinary notice and no policy marker.","purpose":"Preserves loose parent-level source in the reviewed repository scope."}],"flows":[],"trustBoundaries":[]},
        "threats":[],"openQuestions":[{"id":"policy-owner","question":"Does this owner want the policy marker retained?","targetElementIds":["policy-text"]}],
        "summary":{"evidenceType":"Manual owned source description; no vulnerability verdict."}}
    (root / ".kuzushi").mkdir(exist_ok=True)
    save(root / ".kuzushi", "manual-context", document)
    save(evidence, "source-before", source_hashes(root))
    (evidence / "deadline-command.txt").write_text("run semgrep:scan " + json.dumps({"binary":binary,"config":str(rules),"timeoutMs":1}))
    (evidence / "rule-setting.txt").write_text("set semgrepConfig " + json.dumps([str(rules)]))


def counts(root, evidence):
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        return {name:db.execute("select count(*) from " + name).fetchone()[0] if name in tables else None
                for name in ["finding_observations", "investigation_call_reservations", "investigation_work_attempts", "review_decisions"]}


def run_results(root, tool):
    return [(path.parent, json.loads(path.with_name("result.json").read_text()))
            for path in (root / ".kuzushi/v3/runs").glob("*/run.json")
            if json.loads(path.read_text()).get("tool") == tool and path.with_name("result.json").is_file()]


def verify_failure(root, evidence):
    deadline = time.monotonic() + 30
    while not run_results(root, "semgrep:scan") and time.monotonic() < deadline:
        time.sleep(0.1)
    runs = run_results(root, "semgrep:scan")
    assert len(runs) == 1
    run, result = runs[0]
    assert result["status"] == "failed" and "deadline" in result["output"], result
    assert result["data"]["nativeInspections"][0]["configuredLimits"]["timeoutMs"] == 1
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    current = counts(root, evidence)
    assert current["finding_observations"] in [None, 0]
    assert current["investigation_call_reservations"] in [None, 0]
    save(evidence, "deadline-failure", {"runId":run.name,"status":"failed","counts":current,"sourceExecuted":False})


def plan(root, evidence):
    plans = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    plans = [p for p in plans if p["kind"] == "scan-batch"]
    assert len(plans) == 1
    value = plans[0]
    assert len(value["jobs"]) == 3 and value["workers"] == 1
    assert value["baseInput"]["tasks"] == ["semgrep"]
    assert value["baseInput"]["semgrepTimeoutMs"] == 60000
    assert value["baseInput"]["semgrepConfig"] == [str(evidence / "local-rules.yaml")]
    assert all(not value["baseInput"][key] for key in ["triage","verify","autoPatch","patch","pocExecution","dynamicAnalysis"])
    assert value["baseInput"]["threatModelRef"]["revisionId"]
    assert value["baseInput"]["scanContextRef"]["object"]["sizeBytes"] > 0
    assert value["equivalence"].get("model") is None
    assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text()).get("active") is None
    (evidence / "resume-command.txt").write_text("batch " + value["campaignId"])
    return value


def completed(root, evidence, value):
    queue = json.loads((root / ".kuzushi/v3/campaigns" / value["campaignId"] / "queue.json").read_text())
    assert len(queue["jobs"]) == 3
    assert all(job["state"] == "completed" and job["attempts"] == 1 for job in queue["jobs"].values())
    current = counts(root, evidence)
    assert current["finding_observations"] == current["investigation_work_attempts"] == 3
    assert current["investigation_call_reservations"] == 0
    runs = run_results(root, "sast:scan")
    assert len(runs) == 3
    for _, result in runs:
        assert result["status"] == "completed", result["summary"]
        receipt = result["data"]["nativeInspections"][0]
        assert receipt["engine"] == "semgrep" and receipt["configuredLimits"]["timeoutMs"] == 60000
    return current


def exported(root, value):
    report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
    assert report["count"] == 1 and report["findings"][0]["reviewDecision"] == "deferred"
    assert "Owned policy marker needs an owner decision" in json.dumps(report)
    receipt = report["metadata"]["investigation"]
    assert receipt["campaignId"] == value["campaignId"]
    assert receipt["observationCount"] == 3 and receipt["confirmedCount"] == 0
    assert receipt["occurrence"]["completed"] == receipt["occurrence"]["planned"] == 3
    accounting = receipt["allowance"]["currentInvestigation"]
    assert accounting["committedCalls"] == accounting["unresolvedCalls"] == 0
    assert accounting["limits"] == {"maxProviderCalls":1,"protectedReviewCalls":1}


def verify(root, evidence, stage):
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    value = plan(root, evidence)
    if stage == "draft":
        current = counts(root, evidence)
        assert current["finding_observations"] in [None, 0]
        assert not (root / ".kuzushi/v3/campaigns" / value["campaignId"] / "queue.json").exists()
    else:
        deadline = time.monotonic() + 45
        while True:
            try:
                current = completed(root, evidence, value)
                break
            except (AssertionError, FileNotFoundError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)
    if stage in ["exported", "restarted"]:
        assert current["review_decisions"] == 1
        exported(root, value)
    save(evidence, stage + "-check", {"campaignId":value["campaignId"],"counts":current,
        "source":source_hashes(root),"sourceExecuted":False,"remoteRules":False})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "failure":
        verify_failure(root, evidence)
    else:
        verify(root, evidence, stage)
