"""Three owned source-only passes under an explicit zero-provider-call ceiling."""
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

from installed_scope_study import current_counts, native, save

CAMPAIGN = "owned-zero-calls"
TEXT = "# Synthetic public example, no active credential. Never executed.\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"


def run(root, evidence, name, tool, value):
    return native(root, evidence, name, ["run", tool, "--input", json.dumps(value)])


def source_hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["first/fixture.env", "second/fixture.env"]}


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    for name in ["first", "second"]:
        (root / name).mkdir()
        (root / name / "fixture.env").write_text(TEXT)
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "first", "second"], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Owned fixture",
                    "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                    "commit", "-qm", "fixtures: add public examples"], check=True)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    (evidence / "runtime-home.txt").write_text(str(home))
    save(evidence, "source-before", source_hashes(root))
    run(root, evidence, "source-context", "context:build", {"enrichment": False})
    doc = {"version": "1", "methodology": "stride", "title": "Owned public-example context",
           "systemContext": "Two inert files contain the published example credential shape. Neither is an active credential. Source is never executed. Human review must distinguish a scanner signal from a vulnerability.",
           "dfd": {"nodes": [{"id": name, "name": name.title() + " public example", "type": "data-store",
                    "trustZone": "repository", "description": name + "/fixture.env contains inert public example text.",
                    "purpose": "Provides a bounded source observation for operator review."}
                    for name in ["first", "second"]], "flows": [], "trustBoundaries": []},
           "threats": [], "openQuestions": [], "summary": {"evidenceType": "Labeled synthetic source"}}
    save(evidence, "manual-context", doc)
    (evidence / "map-command.txt").write_text("run threat-model:import " + json.dumps({
        "path": str(evidence / "manual-context.json"), "activate": False, "label": "Owned source-only context"}))


def prepare(root, evidence):
    results = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/runs").glob("*/result.json")]
    imported = [r["data"] for r in results if isinstance(r.get("data"), dict) and "modelRef" in r["data"]]
    assert len(imported) == 1
    run(root, evidence, "study-draft", "campaign:study", {"campaignId": CAMPAIGN, "investigationId": CAMPAIGN,
        "trials": 3, "workers": 1, "scanInput": {"taskMode": "manual", "tasks": ["secret-scan"],
        "threatModelRef": imported[0]["modelRef"], "triage": False, "verify": False, "patch": False,
        "autoPatch": False, "pocExecution": False, "dynamicAnalysis": False}})
    assert not (root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json").exists()


def inspect(root, evidence, stage):
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    base = root / ".kuzushi/v3/campaigns" / CAMPAIGN
    plan = json.loads((base / "plan.json").read_text())
    assert plan["workers"] == 1 and len(plan["jobs"]) == 3
    assert all(not plan["baseInput"][key] for key in ["triage", "verify", "patch", "autoPatch", "pocExecution", "dynamicAnalysis"])
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        jobs = json.loads((base / "queue.json").read_text())["jobs"] if (base / "queue.json").exists() else {}
        if len(jobs) == 3 and all(job["state"] == "completed" for job in jobs.values()):
            break
        time.sleep(0.2)
    assert len(jobs) == 3 and all(job["state"] == "completed" and job["attempts"] == 1 for job in jobs.values()), jobs
    assert len({job["runId"] for job in jobs.values()}) == 3
    for job in jobs.values():
        result = json.loads((root / ".kuzushi/v3/runs" / job["runId"] / "result.json").read_text())
        assert result["status"] == "completed" and result["data"]["findingsCount"] == 2
    counts = current_counts(root, evidence)
    assert counts["finding_observations"] == 6 and counts["investigation_work_attempts"] == 3
    assert counts["investigation_call_reservations"] == 0
    allowance = run(root, evidence, "allowance-" + stage, "campaign:allowance", {"investigationId": CAMPAIGN})["data"]
    assert allowance["allowance"]["limits"] == {"maxProviderCalls": 0, "protectedReviewCalls": 0}
    assert allowance["allowance"]["committedCalls"] == allowance["allowance"]["unresolvedCalls"] == 0
    occurrence = native(root, evidence, "occurrence-" + stage, ["findings", "batch", CAMPAIGN, "--json"])
    assert (occurrence["planned"], occurrence["completed"], occurrence["failed"]) == (3, 3, 0)
    assert len(occurrence["rows"]) == 2 and all(row["seen"] == 3 for row in occurrence["rows"])
    save(evidence, "accounting-" + stage, allowance)
    if stage in ["exported", "restarted"]:
        assert counts["review_decisions"] == 2
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert report["count"] == 2
        assert all(f["reviewDecision"] == "rejected_false_positive" for f in report["findings"])
        receipt = report["metadata"]["investigation"]
        accounting = receipt["allowance"]["currentInvestigation"]
        assert accounting["limits"] == {"maxProviderCalls": 0, "protectedReviewCalls": 0}
        assert accounting["committedCalls"] == accounting["unresolvedCalls"] == 0
        assert receipt["campaignId"] == CAMPAIGN and receipt["observationCount"] == 6
        assert receipt["findingCount"] == receipt["reviewedCount"] == 2
        assert receipt["reviewDecisionCounts"] == {"confirmed": 0, "toFix": 0,
            "rejectedFalsePositive": 2, "suppressed": 0, "deferred": 0, "acceptedRisk": 0}
        assert all(f["severity"] == "high" for f in report["findings"])

    save(evidence, stage + "-verified", {"fixedJobs": 3, "completedJobs": 3, "observations": 6,
         "providerRequests": 0, "sourceUnchanged": True, "counts": counts})


if __name__ == "__main__":
    root, evidence = [Path(p).resolve() for p in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "prepare":
        prepare(root, evidence)
    else:
        inspect(root, evidence, stage)
