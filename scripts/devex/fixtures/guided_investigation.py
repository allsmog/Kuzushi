"""Visible Setup-to-Report journey; helpers seed source and only inspect product state."""
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

from secret_settings import ledger, save
from zero_calls import TEXT


def source_hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["first/fixture.env", "second/fixture.env", ".gitignore"]}


def seed(root, evidence, home):
    (evidence / "git-config").write_text("")
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    for name in ["first", "second"]:
        (root / name).mkdir()
        (root / name / "fixture.env").write_text(TEXT)
    (root / ".gitignore").write_text(".kuzushi/\n")
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "first", "second", ".gitignore"], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Owned fixture",
                    "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                    "commit", "-qm", "fixtures: add public examples"], check=True)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    state = root / ".kuzushi"
    state.mkdir(exist_ok=True)
    doc = {"version": "1", "methodology": "stride", "title": "Owned public-example context",
           "systemContext": "Two inert files hold a public example credential shape. Neither is an active credential. Source is never executed. .gitignore excludes generated investigation state.",
           "dfd": {"nodes": [{"id": name, "name": name.title() + " public example", "type": "data-store",
                    "trustZone": "repository", "description": name + "/fixture.env holds inert public example text.",
                    "purpose": "Supplies a bounded source observation for operator review."}
                    for name in ["first", "second"]], "flows": [], "trustBoundaries": []},
           "threats": [], "openQuestions": [], "summary": {"evidenceType": "Manual context over labeled synthetic source"}}
    save(state, "manual-context", doc)
    save(evidence, "source-before", source_hashes(root))


def selected_plan(root, evidence):
    plans = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    assert len(plans) == 1 and plans[0]["kind"] == "scan-batch", plans
    plan = plans[0]
    assert plan["workers"] == 1 and len(plan["jobs"]) == 3
    assert plan["baseInput"]["tasks"] == ["secret-scan"]
    for key in ["triage", "verify", "patch", "autoPatch", "pocExecution", "dynamicAnalysis"]:
        assert not plan["baseInput"][key], key
    results = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/runs").glob("*/result.json")]
    contexts = [r["data"]["modelRef"] for r in results if isinstance(r.get("data"), dict) and "modelRef" in r["data"]]
    assert len(contexts) == 1 and plan["baseInput"]["threatModelRef"] == contexts[0]
    assert plan["baseInput"]["scanContextRef"]["object"]["sizeBytes"] > 0
    assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text()).get("active") is None
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    return plan


def repair_policy(root, evidence):
    before = source_hashes(root)
    assert (root / ".gitignore").read_text() == ".kuzushi/\n"
    assert not list((root / ".kuzushi/v3/runs").glob("*/result.json"))
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    (root / ".gitignore").write_text("# Keep investigation policy trackable.\n")
    after = source_hashes(root)
    assert before["first/fixture.env"] == after["first/fixture.env"]
    assert before["second/fixture.env"] == after["second/fixture.env"]
    save(evidence, "policy-repair", {"before": before, "after": after,
         "reason": "Explicit owned fixture repair after visible launch refusal",
         "helperProductDispatches": 0})
    save(evidence, "source-before", after)


def verify(root, evidence, stage):
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    plan = selected_plan(root, evidence)
    queue = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
    if stage == "draft":
        assert not queue.exists()
        return
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        jobs = json.loads(queue.read_text())["jobs"] if queue.exists() else {}
        if len(jobs) == 3 and all(job["state"] == "completed" for job in jobs.values()):
            break
        time.sleep(0.2)
    assert len(jobs) == 3 and all(job["state"] == "completed" and job["attempts"] == 1 for job in jobs.values()), jobs
    assert len({job["runId"] for job in jobs.values()}) == 3
    with ledger(root, evidence) as db:
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()[0])
        assert approval["limits"] == {"maxProviderCalls": 0, "protectedReviewCalls": 0}
        assert approval["workPlan"]["campaignId"] == plan["campaignId"] and len(approval["workPlan"]["jobs"]) == 3
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 0
        assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 3
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 6
        if stage in ["exported", "restarted"]:
            assert db.execute("select count(*) from review_decisions").fetchone()[0] == 2
    if stage in ["exported", "restarted"]:
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert report["count"] == 2 and all(f["reviewDecision"] == "rejected_false_positive" for f in report["findings"])
        receipt = report["metadata"]["investigation"]
        assert receipt["campaignId"] == plan["campaignId"] and receipt["observationCount"] == 6
        assert receipt["occurrence"]["completed"] == receipt["occurrence"]["planned"] == 3
        assert all(row["seen"] == 3 for row in receipt["occurrence"]["rows"])
    save(evidence, stage + "-verified", {"fixedJobs": 3, "completedJobs": 3, "observations": 6,
        "providerRequests": 0, "sourceUnchangedSincePolicyRepair": True, "helperProductDispatches": 0,
        "planFileSha256": hashlib.sha256((queue.parent / "plan.json").read_bytes()).hexdigest(),
        "campaignId": plan["campaignId"]})


if __name__ == "__main__":
    root, evidence = [Path(p).resolve() for p in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif sys.argv[3] == "repair-policy":
        repair_policy(root, evidence)
    else:
        verify(root, evidence, sys.argv[3])
