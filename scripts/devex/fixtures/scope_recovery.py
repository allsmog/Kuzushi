"""One intercepted scope failure, explicit local correction, no live inference."""
import hashlib
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from rejected_context import execute

CAMPAIGN = "owned-scope-recovery"


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["README.md", "app/main.rs", "shared/contracts.rs", "app.py", "config.env"]}


def candidate():
    def scope(identity, paths, dependencies):
        return {"id": identity, "name": identity.title(), "paths": paths,
                "rationale": "LABELED_OFFLINE_SCOPE_CANDIDATE, no model-quality claim.",
                "sharedDependencies": dependencies, "openQuestions": []}
    return {"schemaVersion": 1, "scopes": [scope("app", ["app"], ["contracts"]),
            scope("integration", ["README.md", "shared"], [])],
            "sharedScope": None, "sharedDiscovery": False, "exclusions": []}


def seed(root, evidence, home):
    for path, text in [("README.md", "Owned inert scope correction fixture.\n"),
                       ("app/main.rs", "// Owned application source. Never executed.\n"),
                       ("shared/contracts.rs", "// Owned shared context. Never executed.\n")]:
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/scope_recovery_provider.mjs", evidence / "provider.mjs")
    invalid = candidate()
    save(evidence, "labeled-invalid-scope", invalid)
    corrected = candidate()
    corrected["scopes"][0]["sharedDependencies"] = ["integration"]
    corrected["scopes"][1]["paths"].extend(["app.py", "config.env"])
    save(evidence, "labeled-corrected-scope", corrected)
    credentials = home / ".kuzushi/scope-recovery-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex": {"access": "offline-scope-recovery-fixture", "expires": 99999999999999}}))
    credentials.chmod(0o600)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    command = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\nlanggraph_bridge_command = ' + json.dumps(command) + '\n[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\nallow_env_token = false\n')
    review = execute(root, home, evidence, "scope-inventory", "pack:scopes", {})
    plan = execute(root, home, evidence, "scope-plan", "campaign:context-study", {
        "campaignId": CAMPAIGN, "investigationId": "owned-scope-recovery-accounting",
        "generationTool": "pack:suggest-scopes", "contextInput": {
            "proposalRef": review["reference"], "threatModelRef": None, "maxOutputTokens": 1024}})
    assert plan["input"]["saveRejectedOutput"] is True
    execute(root, home, evidence, "scope-approval", "campaign:approve-allowance", {
        "investigationId": "owned-scope-recovery-accounting", "expectedRevision": 0,
        "model": "openai-codex:gpt-5.5", "maxProviderCalls": 1, "protectedReviewCalls": 0,
        "reason": "One intercepted offline scope response; no live inference or source execution.",
        "campaignId": CAMPAIGN, "campaignPlanSha256": plan["planSha256"], "campaignJobs": 1, "maxJobAttempts": 1})
    save(evidence, "source-before", hashes(root))
    save(evidence, "plan-before", {"sha256": hashlib.sha256((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "plan.json").read_bytes()).hexdigest()})


def inspect(root, evidence, stage):
    if stage == "paged":
        before = next(evidence.glob("*-editor-40x12.txt")).read_text()
        after = next(evidence.glob("*-editor-page-40x12.txt")).read_text()
        assert before != after, "PageDown must move the displayed compact JSON"
    queue = root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json"
    for _ in range(45):
        jobs = json.loads(queue.read_text())["jobs"] if queue.exists() else {}
        if len(jobs) == 1 and jobs["context-001"]["state"] == "failed":
            break
        time.sleep(1)
    assert len(jobs) == 1
    assert sorted(path.name for path in queue.parent.parent.iterdir() if path.is_dir()) == [CAMPAIGN]
    assert hashlib.sha256((queue.parent / "plan.json").read_bytes()).hexdigest() == json.loads((evidence / "plan-before.json").read_text())["sha256"]
    job = jobs["context-001"]
    assert job["state"] == "failed" and job["attempts"] == job["dispatches"] == 1
    run = root / ".kuzushi/v3/runs" / job["runId"]
    raw = (run / "rejected-scope-output.json").read_bytes()
    output = json.loads(raw)
    assert output["complete"] and json.loads(output["candidate"]) == candidate()
    assert "LABELED_OFFLINE_SCOPE_CANDIDATE" not in (run / "result.json").read_text()
    assert len((evidence / "scope-recovery-calls.jsonl").read_text().splitlines()) == 1
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    assert not (root / ".kuzushi/threat-models/manifest.json").exists()
    revisions = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/scan-scopes/revisions").glob("*.json")]
    expected = 3 if stage == "planning" else (2 if stage in ["corrected", "restarted"] else 1)
    assert len(revisions) == expected
    assert all(record.get("acceptance") is None for record in revisions if record["revision"] < 3)
    if stage == "planning":
        assert next(record for record in revisions if record["revision"] == 3)["acceptance"] is not None
    if expected >= 2:
        corrected = next(record for record in revisions if record["revision"] == 2)
        assert corrected["draft"] == json.loads((evidence / "labeled-corrected-scope.json").read_text())
        assert corrected["correction"]["rejected"]["runId"] == job["runId"]
        assert corrected.get("generation") is None
        if stage == "planning":
            accepted = next(record for record in revisions if record["revision"] == 3)
            assert accepted["draft"] == corrected["draft"] and accepted["correction"] == corrected["correction"]
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 1
        assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 1
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 0
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 0
    save(evidence, stage + "-scope-check", {"fixedJobs": 1, "failedJobs": 1, "interceptedRequests": 1,
        "liveRequests": 0, "acceptedScopes": 1 if stage == "planning" else 0, "scopeRevisions": expected,
        "sourceUnchanged": True, "sourceFilesChecked": 5, "initiallyUncoveredHarnessFiles": ["app.py", "config.env"], "correctedDraftIncludesHarnessFiles": expected >= 2, "sourceExecuted": False, "retainedOutputSha256": hashlib.sha256(raw).hexdigest()})


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        inspect(root, evidence, stage)
