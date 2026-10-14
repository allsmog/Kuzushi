"""Owned inert examples through whole-root and finite exact-scope native scans."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

CAMPAIGN = "owned-secret-settings"
LIMITS = {"secretScanMaxEntries": 8, "secretScanMaxTotalBytes": 1024,
          "secretScanMaxFileBytes": 1024, "secretScanMaxFindings": 10}


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def native(root, evidence, name, tool, value):
    env = dict(os.environ, HOME=str(evidence / "home"))
    for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KUZUSHI_MODEL", "NODE_OPTIONS"]:
        env.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", tool, "--input", json.dumps(value)], env=env, capture_output=True, text=True, timeout=35)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode in [0, 4], (name, result.stderr)
    receipt = json.loads(result.stdout)
    save(evidence, name, receipt)
    return receipt


def hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["first/fixture.env", "second/fixture.env", "excluded.env"]}


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    text = "# Owned synthetic public example. No active credential. Never executed.\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    for name in ["first", "second"]:
        (root / name).mkdir()
        (root / name / "fixture.env").write_text(text + "#" * (900 - len(text)))
    (root / "excluded.env").write_text(text)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    save(evidence, "source-before", hashes(root))
    native(root, evidence, "prepared-context", "context:build", {"enrichment": False})
    whole_root = evidence / "whole-root-target"
    for name in ["first", "second"]:
        (whole_root / name).mkdir(parents=True)
        (whole_root / name / "fixture.env").write_text("#" * 900)
    whole = native(whole_root, evidence, "whole-roots", "sast:scan", {
        "taskMode": "manual", "tasks": ["secret-scan"], "paths": ["first", "second"],
        "triage": False, "verify": False, "autoPatch": False, **LIMITS})
    assert whole["status"] == "partial"
    assert len(whole["data"]["nativeInspections"]) == 2
    assert whole["data"]["nativeInspections"][-1]["totals"]["contentBytesReserved"] == 901
    created = native(root, evidence, "scope-create", "pack:scopes", {})["data"]
    edited = native(root, evidence, "scope-exclude", "pack:scopes", {
        "operation": "edit", "proposalRef": created["reference"],
        "edit": {"action": "exclude-path", "path": "excluded.env", "reason": "Explicit owned fixture exclusion"}})["data"]
    accepted = native(root, evidence, "scope-accept", "pack:scopes", {
        "operation": "accept", "proposalRef": edited["reference"],
        "acknowledgements": {"inventoryLimitations": True, "exclusions": True, "overlappingDiscovery": False}})["data"]
    save(evidence, "scope-reference", {"proposal": accepted["reference"], "scopeId": "repository"})
    document = {"version": "1", "methodology": "stride", "title": "Owned native inspection context",
        "systemContext": "Two inert files contain a public example credential shape. No active credential or vulnerability is claimed. An excluded root file must remain outside discovery.",
        "dfd": {"nodes": [{"id": "first", "name": "First public example", "type": "data-store", "trustZone": "repository",
            "description": "Public example string in first/fixture.env.", "purpose": "Supplies the first bounded source observation."},
            {"id": "second", "name": "Second public example", "type": "data-store", "trustZone": "repository",
            "description": "Public example string in second/fixture.env.", "purpose": "Tests disclosure when the shared read allowance omits another file."}],
            "flows": [], "trustBoundaries": []}, "threats": [],
        "openQuestions": [{"id": "coverage", "question": "Should a separate allowance be approved for files omitted by this finite inspection?", "targetElementIds": ["second"]}],
        "summary": {"evidenceType": "Labeled synthetic metadata"}}
    save(evidence, "manual-context", document)
    (evidence / "map-command.txt").write_text("run threat-model:import " + json.dumps({
        "path": str(evidence / "manual-context.json"), "activate": False, "label": "Owned native inspection context"}))


def prepare(root, evidence):
    results = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/runs").glob("*/result.json")]
    imported = [r["data"] for r in results if isinstance(r.get("data"), dict) and "modelRef" in r["data"]]
    assert len(imported) == 1
    reference = json.loads((evidence / "scope-reference.json").read_text())
    native(root, evidence, "study-draft", "campaign:study", {"campaignId": CAMPAIGN,
        "trials": 3, "workers": 1, "scanInput": {"taskMode": "manual", "tasks": ["secret-scan"],
            "scanScopeRef": reference, "threatModelRef": imported[0]["modelRef"], **LIMITS}})
    inspect(root, evidence, "draft")


def plan(root):
    value = json.loads((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "plan.json").read_text())
    assert value["workers"] == 1 and len(value["jobs"]) == 3
    for key, limit in LIMITS.items():
        assert value["baseInput"][key] == limit
        assert all(job["input"][key] == limit for job in value["jobs"])
    for key in ["triage", "verify", "autoPatch", "patch", "pocExecution", "dynamicAnalysis"]:
        assert not value["baseInput"][key]
    return value


def ledger(root, evidence):
    path = root / ".kuzushi/v3/index.sqlite3"
    wal = path.with_name(path.name + "-wal")
    if wal.exists() and wal.stat().st_size:
        return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    data = path.read_bytes()
    assert not wal.exists() or wal.stat().st_size == 0
    assert path.read_bytes() == data
    snapshot = evidence / "checkpointed-ledger.sqlite3"
    snapshot.write_bytes(data)
    return sqlite3.connect(snapshot.as_uri() + "?mode=ro&immutable=1", uri=True)


def inspect(root, evidence, stage):
    value = plan(root)
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    queue = root / ".kuzushi/v3/campaigns" / CAMPAIGN / "queue.json"
    if stage in ["draft", "settings"]:
        assert not queue.exists()
        if stage == "settings":
            pages = sorted(evidence.glob("*settings-page-*.txt"), key=lambda path: int(path.stem.rsplit("-", 1)[1]))
            text = "".join("".join(line[2:-1].split()) for page in pages for line in page.read_text().splitlines()[3:9])
            for key, limit in LIMITS.items():
                assert "(" + key + ")Value:" + str(limit) in text, "Unreadable limit: " + key
            save(evidence, "settings-verified", {"recordedLimitsRead": LIMITS, "jobsStarted": 0})
        return
    for _ in range(45):
        jobs = json.loads(queue.read_text())["jobs"] if queue.exists() else {}
        if len(jobs) == 3 and all(job["state"] == "failed" for job in jobs.values()):
            break
        time.sleep(1)
    assert len(jobs) == 3 and all(job["state"] == "failed" and job["attempts"] == 1 for job in jobs.values()), jobs
    for job in jobs.values():
        result = json.loads((root / ".kuzushi/v3/runs" / job["runId"] / "result.json").read_text())
        assert result["status"] == "partial" and result["data"]["findingsCount"] == 1
        info = result["data"]["nativeInspections"]
        assert len(info) == 1 and info[0]["selection"] == "exact-files"
        assert info[0]["configuredLimits"]["maxTotalBytes"] == 1024
        assert info[0]["totals"] == {"entriesReserved": 2, "contentBytesReserved": 901, "findings": 1}
        assert info[0]["coverageGaps"]["gaps"]
    with ledger(root, evidence) as db:
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 0
        assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 3
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 3
        if stage in ["exported", "restarted"]:
            assert db.execute("select count(*) from review_decisions").fetchone()[0] == 1
    if stage in ["exported", "restarted"]:
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert report["count"] == 1
        finding = report["findings"][0]
        assert finding["location"]["file"] == "first/fixture.env"
        assert "Owned public example" in json.dumps(report)
        receipt = report["metadata"]["investigation"]
        draft = json.loads((evidence / "study-draft.json").read_text())["data"]
        assert receipt["planSha256"] == draft["planSha256"]
        assert receipt["campaignId"] == CAMPAIGN and receipt["observationCount"] == 3
    save(evidence, stage + "-verified", {"fixedJobs": 3, "attempts": 3, "partialJobs": 3,
        "sourceUnchanged": True, "observations": 3, "providerRequests": 0, "limits": LIMITS})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "prepare":
        prepare(root, evidence)
    else:
        inspect(root, evidence, stage)
