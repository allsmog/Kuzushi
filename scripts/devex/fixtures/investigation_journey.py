"""Fresh Setup through real prepared dispatch, partial work, triage and report. No source execution."""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from contextlib import closing
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
    native_dir = str(Path(os.environ["KUZUSHI_NATIVE_BIN"]).resolve().parent)
    bridge = ["env", "PATH=" + native_dir + os.pathsep + os.environ["PATH"], "node", "--import",
        str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
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


def query_ledger(root):
    # Existing WAL databases may need sidecars initialized before a query.
    # Keep SQL read-only without bypassing WAL contents through immutable mode.
    db = sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True)
    db.execute("PRAGMA query_only=ON")
    return db


def accounting(root, investigation):
    with closing(query_ledger(root)) as db:
        revisions = [json.loads(row[0]) for row in db.execute("select approval_json from investigation_allowance_revisions where investigation_id=? order by revision", (investigation,))]
        reservations = db.execute("select count(*),sum(settled_at is null),sum(review) from investigation_call_reservations").fetchone()
        return {"revisions": revisions, "reservations": list(reservations)}


def verify_run_metadata(root):
    runs = root / ".kuzushi/v3/runs"
    for path in runs.iterdir():
        if path.is_dir():
            assert (path / "run.json").is_file(), "Artifact directory appeared as a run without metadata: " + path.name


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
        frozen = scan["baseInput"]["threatModelDigestRef"]
        assert frozen["schemaVersion"] == 1
        assert all(job["input"]["threatModelDigestRef"] == frozen for job in scan["jobs"])
        (evidence / "scan-command.txt").write_text("campaign " + scan["campaignId"])
        (evidence / "batch-command.txt").write_text("batch " + scan["campaignId"])
        if stage in ["partial", "completed"]:
            terminal = {"completed", "failed"}
            if stage == "partial":
                terminal.add("parked")
            wait_jobs(root, scan, terminal)
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
        verify_run_metadata(root)
        manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
        assert manifest.get("active") is None
        account = accounting(root, context["investigationId"])
        assert account["reservations"] == [expected_calls, 0, 0]
        last = account["revisions"][-1]
        assert last["limits"] == {"maxProviderCalls": 6 if expected_calls == 4 else 5, "protectedReviewCalls": 2}
        model_job = json.loads((root / ".kuzushi/v3/campaigns" / context["campaignId"] / "queue.json").read_text())["jobs"]["context-001"]
        model_result = json.loads((root / ".kuzushi/v3/runs" / model_job["runId"] / "result.json").read_text())
        generated = model_result["data"]["modelRef"]
        if scans:
            assert scans[0]["baseInput"]["threatModelRef"] == generated
            ref = read_native(root, evidence, "context-job-" + stage,
                ["run", "threat-model:read", "--input", json.dumps({"threatModelRef": scans[0]["baseInput"]["threatModelRef"],
                    "threatModelDigestRef": scans[0]["baseInput"]["threatModelDigestRef"]})])["data"]
            assert ref["scannerContextPreview"]["origin"] == "frozen-study"
            assert ref["scannerContextPreview"]["sourceMatchesAtInspection"] is True
            assert ref["document"]["title"] == "Owned greeting application"
            assert ref["sourceState"]["status"] == "matches"
            assert ref["document"]["provenance"]["treeHash"] == model_result["data"]["treeHash"]
    if stage in ["partial-report", "final-report", "restart"]:
        exported = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert exported["count"] == 2
        assert sorted(row["reviewDecision"] for row in exported["findings"]) == ["deferred", "rejected_false_positive"]
        receipt = exported["metadata"]["investigation"]
        assert receipt["reviewedCount"] == 2
        assert receipt["observationCount"] == (4 if expected_calls == 4 else 3)
        assert receipt["occurrence"]["completed"] == (3 if expected_calls == 4 else 2)
        with closing(query_ledger(root)) as db:
            assert db.execute("select count(*) from review_decisions").fetchone()[0] == (3 if expected_calls == 4 else 2)
    (evidence / (stage + "-check.json")).write_text(json.dumps({"stage": stage, "interceptedRequests": expected_calls,
        "liveProviderRequests": 0, "sourceExecuted": False, "sourceUnchanged": True, "activeContextUnchanged": True,
        "contextCampaign": context["campaignId"], "investigationId": context["investigationId"],
        "sourceSha": before["sha"], "dirtyFixture": True, "queueCompletionInjected": False}, indent=2) + "\n")


def hide_context_output(root, evidence):
    manifest = root / ".kuzushi/threat-models/manifest.json"
    retained = evidence / "manifest-before-owned-failure.json"
    assert manifest.is_file() and not retained.exists()
    assert len(calls(evidence)) == 4
    shutil.copy2(manifest, retained)
    manifest.unlink()
    context = next(plan for plan in plans(root) if plan["kind"] == "context-study")
    (evidence / "context-command.txt").write_text("campaign " + context["campaignId"])
    (evidence / "owned-failure-start.json").write_text(json.dumps({"scope":"Temporary fixture metadata only", "sourceUnchanged": source_hashes(root) == json.loads((evidence / "before.json").read_text())["sources"], "interceptedRequests":4, "liveProviderRequests":0}) + "\n")


def restore_context_output(root, evidence):
    manifest = root / ".kuzushi/threat-models/manifest.json"
    retained = evidence / "manifest-before-owned-failure.json"
    assert not manifest.exists() and retained.is_file()
    assert len(calls(evidence)) == 4
    shutil.copy2(retained, manifest)
    assert manifest.read_bytes() == retained.read_bytes()
    verify(root, evidence, "restart")
    (evidence / "owned-failure-restored.json").write_text(json.dumps({"manifestBytesRestored":True,"sourceUnchanged":True,"modelRequestsAdded":0,"liveProviderRequests":0,"sourceExecuted":False}) + "\n")


if __name__ == "__main__":
    root, evidence, stage, *homes = sys.argv[1:]
    root, evidence = Path(root).resolve(), Path(evidence).resolve()
    if stage == "seed":
        seed(root, evidence, Path(homes[0]).resolve())
    elif stage == "hide-context":
        hide_context_output(root, evidence)
    elif stage == "restore-context":
        restore_context_output(root, evidence)
    else:
        verify(root, evidence, stage)
