"""Real finite policy discovery over owned inert metadata. No model or source execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source_hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["package.json", "main.rs"]}


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "package.json").write_text('{"name":"owned-inert-policy-study"}\n')
    (root / "main.rs").write_text("// SPDX-License-Identifier: MIT\n// Owned inert metadata. Never built or executed.\n")
    (evidence / "original-main.rs").write_bytes((root / "main.rs").read_bytes())
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    document = {"version":"1", "methodology":"stride", "title":"Owned package policy context",
        "systemContext":"This owned inert fixture has package.json naming owned-inert-policy-study without a license field and main.rs carrying an MIT SPDX header. No executable application or runtime data flow is implemented or inferred.",
        "dfd":{"nodes":[{"id":"manifest","name":"Package manifest","type":"data-store","trustZone":"repository",
            "description":"package.json contains a package name and no declared license.","purpose":"Holds declared package metadata for owner policy review."},
            {"id":"headers","name":"Source headers","type":"data-store","trustZone":"repository",
             "description":"main.rs contains an MIT SPDX comment and no executed source.","purpose":"Retains source header policy evidence."}],"flows":[],"trustBoundaries":[]},
        "threats":[],"openQuestions":[{"id":"license-owner","question":"Which license should the package manifest declare?","targetElementIds":["manifest"]}],
        "summary":{"evidenceType":"Manually supplied owned metadata; no vulnerability verdict."}}
    save(evidence, "manual-context", document)
    state = root / ".kuzushi"
    state.mkdir(exist_ok=True)
    save(state, "manual-context", document)
    save(evidence, "source-before", source_hashes(root))


def scan_plan(root):
    plans = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    plans = [p for p in plans if p["kind"] == "scan-batch"]
    assert len(plans) == 1, plans
    plan = plans[0]
    assert len(plan["jobs"]) == 3 and plan["workers"] == 1
    assert plan["baseInput"]["tasks"] == ["license-scan"]
    for key in ["triage", "verify", "autoPatch", "patch", "pocExecution", "dynamicAnalysis"]:
        assert not plan["baseInput"][key], (key, plan)
    assert plan["baseInput"]["scanContextRef"]["object"]["sizeBytes"] > 0
    imports = []
    for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
        if json.loads(path.read_text()).get("tool") == "threat-model:import":
            imports.append(json.loads(path.with_name("result.json").read_text())["data"])
    assert len(imports) == 1 and plan["baseInput"]["threatModelRef"] == imports[0]["modelRef"]
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest.get("active") is None
    assert plan["equivalence"].get("model") is None
    return plan


def ledger_counts(root):
    path = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name:db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0 for name in
                  ["finding_observations", "investigation_call_reservations", "investigation_work_attempts", "review_decisions"]}
    assert counts["investigation_call_reservations"] == 0, counts
    return counts


def verify_allowance(root, plan):
    path = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
        row = db.execute("select approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()
    approval = json.loads(row[0])
    assert approval["limits"] == {"maxProviderCalls":1,"protectedReviewCalls":1}
    assert approval["workPlan"]["campaignId"] == plan["campaignId"]
    assert len(approval["workPlan"]["jobs"]) == 3
    assert all(job["maxAttempts"] == 1 for job in approval["workPlan"]["jobs"])


def verify_report(root, plan):
    value = json.loads((root / ".kuzushi/reports/findings.json").read_text())
    assert value["count"] == 1
    text = json.dumps(value)
    assert "Owned package policy needs an owner decision" in text and "deferred" in text
    assert "Package manifest does not declare a license" in text
    finding = value["findings"][0]
    assert finding["staticProofState"] == "signal_only"
    assert finding["reviewDecision"] == "deferred" and finding["lifecycleStatus"] == "candidate"
    receipt = value["metadata"]["investigation"]
    assert receipt["campaignId"] == plan["campaignId"] and receipt["workers"] == 1
    assert receipt["findingCount"] == receipt["reviewedCount"] == 1
    assert receipt["confirmedCount"] == 0 and receipt["observationCount"] == 3
    assert len(receipt["attempts"]) == len(receipt["observationRunRefs"]) == 3
    assert receipt["equivalence"]["components"]["threatModel"] == plan["baseInput"]["threatModelRef"]
    assert receipt["equivalence"]["components"]["workspaceIdentity"] == plan["equivalence"]["workspaceIdentity"]
    assert receipt["occurrence"]["completed"] == receipt["occurrence"]["planned"] == 3
    accounting = receipt["allowance"]["currentInvestigation"]
    assert accounting["committedCalls"] == accounting["unresolvedCalls"] == accounting["reviewCalls"] == 0
    assert accounting["limits"] == {"maxProviderCalls":1,"protectedReviewCalls":1}
    assert accounting["workPlan"]["planSha256"] == receipt["planSha256"]
    assert all(attempt["scan"]["outcome"] == "completed" for attempt in receipt["attempts"])
    sidecar = json.loads((root / ".kuzushi/reports/findings.json.investigation.json").read_text())
    assert sidecar == receipt


def occurrence_report(root, evidence, campaign):
    repo = Path(__file__).resolve().parents[3]
    env = dict(os.environ, HOME=str(evidence / "home"))
    result = subprocess.run([str(repo / "target/debug/kuzushi"), "--target", str(root),
        "findings", "batch", campaign, "--json"], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    save(evidence, "occurrence", value)
    return value


def verify(root, evidence, stage):
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    plan = scan_plan(root)
    campaign = root / ".kuzushi/v3/campaigns" / plan["campaignId"]
    (evidence / "resume-command.txt").write_text("batch " + plan["campaignId"])
    counts = ledger_counts(root)
    if stage == "draft":
        assert not (campaign / "queue.json").exists()
        assert counts["finding_observations"] == counts["investigation_work_attempts"] == 0
    else:
        verify_allowance(root, plan)
        queue = json.loads((campaign / "queue.json").read_text())
        assert len(queue["jobs"]) == 3
        assert all(job["state"] == "completed" and job["attempts"] == 1 for job in queue["jobs"].values())
        assert counts["finding_observations"] == counts["investigation_work_attempts"] == 3
        occurrence = occurrence_report(root, evidence, plan["campaignId"])
        assert occurrence["completed"] == occurrence["planned"] == 3 and len(occurrence["rows"]) == 1
        assert occurrence["rows"][0]["seen"] == 3
    if stage in ["exported", "restarted"]:
        assert counts["review_decisions"] == 1
        verify_report(root, plan)
    save(evidence, stage + "-check", {"campaignId":plan["campaignId"],"counts":counts,"source":source_hashes(root)})


def wait_completed(root, evidence):
    deadline = time.monotonic() + 45
    while True:
        try:
            verify(root, evidence, "completed")
            return
        except (AssertionError, FileNotFoundError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)


def drift(root, evidence):
    source = root / "main.rs"
    source.write_bytes((evidence / "original-main.rs").read_bytes() + b"// Explicit owned metadata drift.\n")
    assert source_hashes(root) != json.loads((evidence / "source-before.json").read_text())


def restore(root, evidence):
    counts = ledger_counts(root)
    assert counts["finding_observations"] == counts["investigation_work_attempts"] == 0, counts
    plan = scan_plan(root)
    queue_path = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
    if queue_path.exists():
        queue = json.loads(queue_path.read_text())
        assert all(job["attempts"] == 0 for job in queue["jobs"].values())
    save(evidence, "stale-source-rejected", {"counts":counts,"approvedJobs":3,"sourceChanged":True})
    (root / "main.rs").write_bytes((evidence / "original-main.rs").read_bytes())
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())


root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
stage = sys.argv[3]
if stage == "seed":
    seed(root, evidence, Path(sys.argv[4]).resolve())
elif stage == "completed":
    wait_completed(root, evidence)
elif stage == "drift":
    drift(root, evidence)
elif stage == "restore":
    restore(root, evidence)
else:
    verify(root, evidence, stage)
