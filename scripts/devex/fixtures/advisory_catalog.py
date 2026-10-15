"""Owned offline advisories and intercepted drafting with protected Review."""
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path
from variant_draft import seed as draft_seed
from advisory_observations import decision_digest
from rejected_context import execute

RESEARCH = "threat-intel:research"
HARVEST = "threat-intel:harvest"


def record(name):
    return {"id": name, "source": "claimed-source", "description": "Labeled owned advisory; no defect claimed",
        "cwes": ["CWE-79"], "affected": [], "patches": [{"url": "https://example.invalid/owned.diff", "kind": "diff"}], "raw": {}}


def seed(root, evidence, home):
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({"name": "owned-app", "dependencies": {"owned-lib": "1.0.0"}}))
    draft_seed(root, evidence, home)
    shutil.copyfile(Path(__file__).with_name("advisory_catalog_provider.mjs"), evidence / "provider.mjs")
    execute(root, home, evidence, "catalog-approval", "campaign:approve-allowance", {
        "investigationId": "owned-pattern", "expectedRevision": 1, "model": "openai-codex:gpt-5.5",
        "maxProviderCalls": 3, "protectedReviewCalls": 1, "reason": "Two explicitly requested intercepted catalog actions"})
    (evidence / "decision-before.sha256").write_text(decision_digest(root))
    (evidence / "package-before.sha256").write_text(hashlib.sha256((root / "package.json").read_bytes()).hexdigest())
    common = {"offline": True, "regressionGate": False, "maxCves": 2,
        "fixtures": {name: record(name) for name in ["OWNED-ONE", "OWNED-TWO", "OWNED-THREE"]},
        "patchFixtures": {"https://example.invalid/owned.diff": "--- a/hello.txt\n+++ b/hello.txt\n-Owned greeting\n+Owned changed greeting\n"}}
    research = dict(common, maxPackages=1, maxCvesPerPackage=1,
        osvFixtures={"owned-lib": [{"id": "OWNED-ONE", "summary": "Labeled owned metadata"}]},
        outputPath=".kuzushi/catalogs/research-draft.toml", allowanceRef=reference("research"))
    harvest = dict(common, cves=["OWNED-TWO", "OWNED-THREE"],
        outputPath=".kuzushi/catalogs/harvest-draft.toml", allowanceRef=reference("harvest"))
    (evidence / "research.txt").write_text("run " + RESEARCH + " " + json.dumps(research))
    (evidence / "harvest.txt").write_text("run " + HARVEST + " " + json.dumps(harvest))


def reference(work):
    return {"schemaVersion": 1, "investigationId": "owned-pattern", "revision": 2, "workId": work}


def run_result(root, tool):
    deadline = time.monotonic() + 20
    rows = []
    while time.monotonic() < deadline:
        rows = [(p.parent, json.loads(p.read_text())) for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
        rows = [(p, row) for p, row in rows if row.get("tool") == tool]
        if len(rows) == 1 and rows[0][1]["status"] != "running":
            break
        time.sleep(.05)
    assert len(rows) == 1 and rows[0][1]["status"] == "partial", rows
    path, run = rows[0]
    assert not run.get("phase")
    return path, run, json.loads((path / "result.json").read_text())["data"]


def verify(root, evidence, stage):
    assert decision_digest(root) == (evidence / "decision-before.sha256").read_text()
    for name, saved in [("hello.txt", "source-before.sha256"), ("package.json", "package-before.sha256")]:
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == (evidence / saved).read_text()
    active = json.loads((evidence / "active-before.json").read_text())
    assert hashlib.sha256(Path(active["path"]).read_bytes()).hexdigest() == active["sha256"]
    calls = evidence / "catalog-calls.jsonl"
    if stage == "before":
        assert not calls.exists()
        return
    path, run, research = run_result(root, RESEARCH)
    assert research["sourceVerified"] is False and research["accepted"] is False
    assert research["cveCount"] == 1 and research["harvest"]["data"]["summary"]["harvested"] == 1
    count = 1 if stage == "research" else 2
    if stage == "research":
        (evidence / "research-result.sha256").write_text(hashlib.sha256((path / "result.json").read_bytes()).hexdigest())
        (evidence / "replay.txt").write_text("replay " + run["runId"])
    else:
        assert hashlib.sha256((path / "result.json").read_bytes()).hexdigest() == (evidence / "research-result.sha256").read_text()
        path, run, harvest = run_result(root, HARVEST)
        assert harvest["accepted"] is False and harvest["patternsVerified"] is False
        assert harvest["summary"]["harvested"] == 1 and harvest["summary"]["deferred"] == 1
        assert harvest["perCve"][1]["status"] == "deferred"
        child = harvest["perCve"][0]["extractionReceipt"]
        assert child["data"]["accepted"] is False and child["data"]["sourceReceipt"]["complete"] is True
        assert "source claims unverified" in Path(harvest["outputPath"]).read_text()
        digest = hashlib.sha256((path / "result.json").read_bytes()).hexdigest()
        if stage == "harvest":
            (evidence / "harvest-result.sha256").write_text(digest)
            (evidence / "replay-harvest.txt").write_text("replay " + run["runId"])
        else:
            assert digest == (evidence / "harvest-result.sha256").read_text()
    assert len(calls.read_text().splitlines()) == count
    account = execute(root, Path(os.environ["HOME"]), evidence, "allowance-" + stage,
        "campaign:allowance", {"investigationId": "owned-pattern"})["allowance"]
    assert account["committedCalls"] == count and account["reviewCalls"] == 0 and account["limits"]["protectedReviewCalls"] == 1
    lessons = execute(root, Path(os.environ["HOME"]), evidence, "lessons-" + stage, "findings:lessons", {})
    assert lessons["rows"] == []
    (evidence / (stage + "-check.json")).write_text(json.dumps({"interceptedRequests": count, "liveRequests": 0,
        "sourceExecution": False, "sourceUnchanged": True, "exactHumanDecisionPreserved": True,
        "activeContextUnchanged": True, "acceptedLessons": 0, "committedCalls": count,
        "protectedReviewCalls": 1, "catalogAccepted": False, "phaseContinuation": False}, indent=2) + "\n")


if __name__ == "__main__":
    stage, root, evidence, *home = sys.argv[1:]
    root, evidence = Path(root).resolve(), Path(evidence).resolve()
    if stage == "seed":
        seed(root, evidence, Path(home[0]).resolve())
    else:
        verify(root, evidence, stage)
