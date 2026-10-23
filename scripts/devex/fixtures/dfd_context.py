"""Bounded diagram context through the real adapter with intercepted transport only."""
import hashlib
import json
import os
import shutil
import sqlite3
import sys
from pathlib import Path

from context_comparison import run_tool
from dfd_study import graph
from investigation_journey import plans, seed, wait_jobs

SELECTED = [" app /lib.py", "app/lib.py"]
FILES = SELECTED + ["app/lib.py.extra.py", "loose.py"]


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in FILES}


def prepare(root, evidence, home):
    seed(root, evidence, home)
    for name in ["main.rs", "app.py", "config.env"]:
        (root / name).unlink()
    for name, marker in zip(FILES, ["SPACED_EVIDENCE", "ORDINARY_EVIDENCE", "UNSELECTED_SIBLING", "UNSELECTED_ROOT"]):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# Owned inert source. " + marker + "\n")
    result = run_tool(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, "inactive-alpha",
        "threat-model:import", {"document": graph("Alpha", SELECTED), "label": "Alpha", "activate": False})
    save(evidence, "dfd-context-before", {"selected": result["data"]["modelRef"], "sources": hashes(root)})
    save(root / ".kuzushi", "manual-context", graph("Beta", [FILES[2]]))
    shutil.copyfile(Path(__file__).with_name("dfd_context_provider.mjs"), evidence / "provider.mjs")


def verify(root, evidence, stage):
    before = json.loads((evidence / "dfd-context-before.json").read_text())
    assert hashes(root) == before["sources"]
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] != before["selected"]
    assert not (root / ".kuzushi/project-model/scopes.json").exists()
    entries = plans(root)
    if stage == "navigation":
        assert not entries and not (evidence / "dfd-context-calls.jsonl").exists()
        before["active"] = manifest["active"]
        save(evidence, "dfd-context-before", before)
        return
    assert manifest["active"] == before["active"]
    assert len(entries) == 1 and entries[0]["kind"] == "context-study"
    plan = entries[0]
    assert plan["workers"] == 1 and len(plan["jobs"]) == 1
    job = plan["jobs"][0]
    assert job["tool"] == "threat-model:build"
    assert job["input"]["sourcePaths"] == SELECTED
    assert job["input"]["inheritedContextRef"] == before["selected"]
    assert not plan.get("preparationJobs")
    assert job["input"]["activate"] is False and job["input"]["pipeline"] == "single"
    if stage == "draft":
        assert not (evidence / "dfd-context-calls.jsonl").exists()
        save(evidence, "dfd-context-draft", {"fixedJobs": 1, "selected": SELECTED, "liveRequests": 0})
        return
    wait_jobs(root, plan, {"completed"})
    calls = [json.loads(line) for line in (evidence / "dfd-context-calls.jsonl").read_text().splitlines()]
    assert len(calls) == 1 and calls[0]["liveRequests"] == 0
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert len(manifest["models"]) == 3 and manifest["active"] == before["active"]
    queue = json.loads((root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json").read_text())["jobs"]
    outcome = next(iter(queue.values()))
    assert outcome["attempts"] == outcome["dispatches"] == 1
    result = json.loads((root / ".kuzushi/v3/runs" / outcome["runId"] / "result.json").read_text())
    assert result["status"] == "completed" and not result["data"]["activated"]
    receipt = result["data"]["document"]["provenance"]["fileContext"]["receipt"]
    assert receipt["sourcePaths"] == SELECTED and receipt["inheritedContextRef"] == before["selected"]
    assert receipt["synthesisRequests"] == 1 and not receipt["completeRepositoryCoverage"]
    assert [file["path"] for file in receipt["sourceEvidence"]["files"]] == SELECTED
    assert all(file["scopeRole"] == "evidence" for file in receipt["sourceEvidence"]["files"])
    with sqlite3.connect(root / ".kuzushi/v3/index.sqlite3") as db:
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 1
        assert db.execute("select count(*) from investigation_call_reservations where settled_at is null or review=1").fetchone()[0] == 0
    (evidence / "dfd-context-resume.txt").write_text("campaign " + plan["campaignId"])
    save(evidence, "dfd-context-completed", {"fixedJobs": 1, "interceptedRequests": 1, "liveRequests": 0,
        "sourceExecuted": False, "activeUnchanged": True, "sourceUnchanged": True, "modelRef": result["data"]["modelRef"]})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, sys.argv[3])
