"""Fresh Setup through real prepared dispatch, partial work, triage and report. No source execution."""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


def seed(root, evidence, home):
    assert root == evidence / "fixture-target" and (root / ".git").is_dir()
    (root / "main.rs").write_text('// Labeled owned greeting. Never executed.\nfn main() { println!("hello"); }\n')
    (root / "app.py").write_text('# Labeled alternative greeting. Never executed.\nprint("hello")\n')
    (root / "config.env").write_text('# Owned fixture has no credentials or external services.\n')
    repo = Path(__file__).resolve().parents[3]
    objects = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "--path-format=absolute", "--git-path", "objects"], text=True).strip()
    sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    info = root / ".git/objects/info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "alternates").write_text(objects + "\n")
    subprocess.run(["git", "-C", str(root), "update-ref", "HEAD", sha], check=True)
    shutil.copyfile(repo / "scripts/devex/fixtures/investigation_provider.mjs", evidence / "provider.mjs")
    credential = home / ".kuzushi/investigation-credentials.json"
    credential.parent.mkdir(parents=True, exist_ok=True)
    credential.write_text(json.dumps({"openai-codex": {"access": "offline-investigation-fixture", "expires": 99999999999999}}))
    credential.chmod(0o600)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    bridge = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\nlanggraph_bridge_command = ' + json.dumps(bridge)
        + '\n[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credential)) + '\nallow_env_token = false\n')
    (evidence / "before.json").write_text(json.dumps({"sha": sha, "sources": source_hashes(root),
        "newCommitCreated": False, "fixtureWorktreeMatchesCommit": False}))


def source_hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ["main.rs", "app.py", "config.env"]}


def plans(root):
    return [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]


def calls(evidence):
    path = evidence / "investigation-calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def read_native(root, evidence, name, arguments):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root), *arguments],
        capture_output=True, text=True, timeout=30, check=True)
    (evidence / (name + ".json")).write_text(result.stdout)
    return json.loads(result.stdout)


def wait_jobs(root, plan, terminal):
    path = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
    deadline = time.monotonic() + 55
    while time.monotonic() < deadline:
        if path.exists():
            jobs = json.loads(path.read_text())["jobs"]
            if all(job["state"] in terminal for job in jobs.values()):
                return jobs
        time.sleep(0.5)
    raise RuntimeError("Fixed native jobs did not reach the expected terminal state")


def accounting(root, investigation):
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        revisions = [json.loads(row[0]) for row in db.execute("select approval_json from investigation_allowance_revisions where investigation_id=? order by revision", (investigation,))]
        reservations = db.execute("select count(*),sum(settled_at is null),sum(review) from investigation_call_reservations").fetchone()
        return {"revisions": revisions, "reservations": list(reservations)}


def verify(root, evidence, stage):
    before = json.loads((evidence / "before.json").read_text())
    assert subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip() == before["sha"]
    assert source_hashes(root) == before["sources"]
    context = [plan for plan in plans(root) if plan["kind"] == "context-study"]
    assert len(context) == 1
    context = context[0]
    assert [job["tool"] for job in context["jobs"]] == ["context:build", "entry-points:extract", "threat-model:build"]
    assert context["workers"] == 1 and len(context["jobs"]) == 3
    expected_calls = 0 if stage == "map-draft" else 1 if stage in ["map-completed", "map-accepted", "scan-draft", "scan-approved"] else 4 if stage in ["completed", "final-report", "restart"] else 3
    if stage == "map-completed":
        wait_jobs(root, context, {"completed"})
    scans = [plan for plan in plans(root) if plan["kind"] == "scan-batch"]
    if stage not in ["map-draft", "map-completed", "map-accepted"]:
        assert len(scans) == 1
        scan = scans[0]
        assert scan["investigationId"] == context["investigationId"]
        assert len(scan["jobs"]) == 3 and scan["workers"] == 1
        assert scan["baseInput"]["tasks"] == ["agentic"]
        assert all(scan["baseInput"][key] is False for key in ["triage", "verify", "autoPatch"])
        assert scan["baseInput"]["scanContextRef"]["schemaVersion"] == 1
        assert scan["equivalence"]["supportingContextSha256"]
        assert all(job["input"]["scanContextRef"] == scan["baseInput"]["scanContextRef"] for job in scan["jobs"])
        (evidence / "scan-command.txt").write_text("campaign " + scan["campaignId"])
        (evidence / "batch-command.txt").write_text("batch " + scan["campaignId"])
        if stage in ["partial", "completed"]:
            wait_jobs(root, scan, {"completed", "parked", "failed"})
        if expected_calls >= 3:
            occurrence = read_native(root, evidence, "occurrence-" + stage, ["findings", "batch", scan["campaignId"], "--json"])
            assert occurrence["completed"] == (3 if expected_calls == 4 else 2)
            assert occurrence["planned"] == 3
            assert occurrence["failed"] == 0 and occurrence["pending"] == (0 if expected_calls == 4 else 1)
            assert sorted(row["seen"] for row in occurrence["rows"]) == ([2, 2] if expected_calls == 4 else [1, 2])
            for row in occurrence["rows"]:
                title = row["representativeTitle"]
                kind = "recurring" if "recurring" in title else "later-only"
                (evidence / ("open-" + kind + ".txt")).write_text("open " + row["representativeFingerprint"])
    request_receipts = calls(evidence)
    assert len(request_receipts) == expected_calls
    assert all(call["liveProviderRequests"] == 0 and call["toolCallsReturned"] == 0 for call in request_receipts)
    scan_requests = [call for call in request_receipts if call["stage"] == "scan"]
    assert len({call["bridgePid"] for call in scan_requests}) == len(scan_requests)
    assert len({call["inputSha256"] for call in scan_requests}) <= 1, "Discovery context changed within the approved study"
    assert len({call["instructionsSha256"] for call in scan_requests}) <= 1
    if expected_calls:
        manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
        assert manifest.get("active") is None
        account = accounting(root, context["investigationId"])
        assert account["reservations"] == [expected_calls, 0, 0]
        last = account["revisions"][-1]
        assert last["limits"] == {"maxProviderCalls": 6 if expected_calls == 4 else 5, "protectedReviewCalls": 2}
        model_job = json.loads((root / ".kuzushi/v3/campaigns" / context["campaignId"] / "queue.json").read_text())["jobs"]["context-001"]
        generated = json.loads((root / ".kuzushi/v3/runs" / model_job["runId"] / "result.json").read_text())["data"]["modelRef"]
        if scans:
            assert scans[0]["baseInput"]["threatModelRef"] == generated
            ref = read_native(root, evidence, "context-job-" + stage,
                ["run", "threat-model:read", "--input", json.dumps({"threatModelRef": scans[0]["baseInput"]["threatModelRef"]})])["data"]
            assert ref["document"]["title"] == "Owned greeting application"
    if stage in ["partial-report", "final-report", "restart"]:
        exported = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert exported["count"] == 2
        assert sorted(row["reviewDecision"] for row in exported["findings"]) == ["deferred", "rejected_false_positive"]
        receipt = exported["metadata"]["investigation"]
        assert receipt["reviewedCount"] == 2
        assert receipt["observationCount"] == (4 if expected_calls == 4 else 3)
        assert receipt["occurrence"]["completed"] == (3 if expected_calls == 4 else 2)
        with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
            assert db.execute("select count(*) from review_decisions").fetchone()[0] == (3 if expected_calls == 4 else 2)
    (evidence / (stage + "-check.json")).write_text(json.dumps({"stage": stage, "interceptedRequests": expected_calls,
        "liveProviderRequests": 0, "sourceExecuted": False, "sourceUnchanged": True, "activeContextUnchanged": True,
        "contextCampaign": context["campaignId"], "investigationId": context["investigationId"],
        "sourceSha": before["sha"], "dirtyFixture": True, "queueCompletionInjected": False}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage, *homes = sys.argv[1:]
    root, evidence = Path(root).resolve(), Path(evidence).resolve()
    if stage == "seed":
        seed(root, evidence, Path(homes[0]).resolve())
    else:
        verify(root, evidence, stage)
