"""Owned wide-repository context test. Source is never executed; transport is intercepted."""
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from dfd_context import FILES, SELECTED, hashes, save
from dfd_study import graph
from investigation_journey import accounting, plans, seed

UNSELECTED = "zz-fill/zzzz-unselected.rs"


def run(root, evidence, label, tool, value, success=True):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", tool, "--input", json.dumps(value)], capture_output=True, text=True, timeout=240)
    (evidence / (label + ".stdout")).write_text(result.stdout)
    (evidence / (label + ".stderr")).write_text(result.stderr)
    if success:
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    assert result.returncode != 0
    return result.stderr


def prepare(root, evidence, home):
    seed(root, evidence, home)
    for name in ["main.rs", "app.py", "config.env"]:
        (root / name).unlink()
    for name, marker in zip(FILES, ["SPACED_EVIDENCE", "ORDINARY_EVIDENCE", "UNSELECTED_SIBLING", "UNSELECTED_ROOT"]):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# Owned inert source. " + marker + "\n")
    filler = root / "zz-fill"
    filler.mkdir()
    for index in range(100_001):
        (filler / ("file-%06d.txt" % index)).touch()
    (root / UNSELECTED).write_text("// UNSELECTED_WIDE_SOURCE. Never executed.\n")
    imported = run(root, evidence, "import-alpha", "threat-model:import",
        {"document": graph("Alpha", SELECTED), "label": "Alpha", "activate": True})
    run(root, evidence, "bounded-inventory", "pack:scopes", {"operation": "create"})
    objects = list((root / ".kuzushi/v3/scan-scopes/inventories").glob("*.json"))
    assert len(objects) == 1
    members = set(json.loads(objects[0].read_text())["inspection"]["files"])
    assert all(path in members for path in SELECTED)
    unlisted = next("zz-fill/file-%06d.txt" % index for index in range(100_001)
        if "zz-fill/file-%06d.txt" % index not in members)
    assert (root / unlisted).is_file()
    save(evidence, "partial-before", {"active": imported["data"]["modelRef"], "sources": hashes(root),
        "fillerCount": 100_001, "unlistedPath": unlisted,
        "newCommitCreated": False, "sourceMatchesBorrowedSha": False})
    error = run(root, evidence, "unlisted-selection", "campaign:context-study",
        {"campaignId": "refused-unlisted", "investigationId": "owned-wide-context", "contextInput": {
            "sourcePaths": [unlisted], "inheritedContextRef": imported["data"]["modelRef"]}}, False)
    assert "absent from the bounded inventory" in error and unlisted in error
    assert not plans(root)
    review = run(root, evidence, "map-review", "campaign:context-map",
        {"threatModelRef": imported["data"]["modelRef"]})
    assert review["data"]["modelRef"] == imported["data"]["modelRef"]
    assert review["data"]["mapOutcome"] == "completed"
    shutil.copyfile(Path(__file__).with_name("dfd_context_provider.mjs"), evidence / "base-provider.mjs")
    shutil.copyfile(Path(__file__).with_name("partial_evidence_provider.mjs"), evidence / "provider.mjs")


def fixed_plan(root):
    entries = plans(root)
    assert len(entries) == 1
    plan = entries[0]
    assert len(plan["jobs"]) == 1 and plan["workers"] == 1
    assert plan["jobs"][0]["tool"] == "threat-model:build"
    assert plan["jobs"][0]["input"]["sourcePaths"] == SELECTED
    return plan


def check_inventory(root, inventory, unlisted):
    assert inventory["enumerationComplete"] is False
    assert inventory["selectedMembershipKnown"] is True
    assert inventory["entries"] == inventory["maxEntries"] == 100_000
    assert inventory["enumeratedFiles"] < 100_003
    assert inventory["maxInspectedBytes"] == 512 * 1024 * 1024
    assert inventory["maxFileInspectionBytes"] == 256 * 1024
    assert "entry cap" in inventory["truncation"]["reason"]
    assert inventory["completeRepositoryCoverage"] is False
    objects = list((root / ".kuzushi/v3/scan-scopes/inventories").glob("*.json"))
    assert len(objects) == 1 and objects[0].stem == inventory["inventoryHash"]
    saved = json.loads(objects[0].read_text())
    assert all(path in saved["inspection"]["files"] for path in SELECTED)
    assert unlisted not in saved["inspection"]["files"]


def completed(root, plan):
    queue = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        if queue.exists():
            jobs = list(json.loads(queue.read_text())["jobs"].values())
            if all(job["state"] in ["completed", "failed", "partial", "interrupted", "parked"] for job in jobs):
                assert len(jobs) == 1 and jobs[0]["state"] == "completed", jobs
                assert jobs[0]["attempts"] == jobs[0]["dispatches"] == 1
                return jobs[0]
        time.sleep(0.5)
    raise RuntimeError("The existing fixed job has not reached a terminal state")


def verify(root, evidence, stage):
    before = json.loads((evidence / "partial-before.json").read_text())
    assert hashes(root) == before["sources"]
    assert len(list((root / "zz-fill").glob("file-*.txt"))) == before["fillerCount"]
    plan = fixed_plan(root)
    check_inventory(root, plan["sourceInventory"], before["unlistedPath"])
    calls = evidence / "dfd-context-calls.jsonl"
    if stage == "draft":
        assert not calls.exists()
        save(evidence, "partial-draft-check", {"fixedJobs": 1, "sourceInventory": plan["sourceInventory"], "liveRequests": 0})
        return
    job = completed(root, plan)
    output = json.loads((root / ".kuzushi/v3/runs" / job["runId"] / "result.json").read_text())
    receipt = output["data"]["document"]["provenance"]["fileContext"]["receipt"]
    check_inventory(root, receipt["inventory"], before["unlistedPath"])
    assert receipt["inventory"] == plan["sourceInventory"]
    assert receipt["sourcePartial"] is False
    assert [file["path"] for file in receipt["sourceEvidence"]["files"]] == SELECTED
    assert len(calls.read_text().splitlines()) == 1
    ledger = accounting(root, plan["investigationId"])
    assert ledger["reservations"] == [1, 0, 0]
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == before["active"] and len(manifest["models"]) == 2
    (evidence / "resume.txt").write_text("campaign " + plan["campaignId"])
    save(evidence, "partial-" + stage + "-check", {"fixedJobs": 1, "interceptedRequests": 1, "liveRequests": 0,
        "sourceExecuted": False, "selectedSourceUnchanged": True, "activeUnchanged": True, "accounting": ledger,
        "sourceInventory": receipt["inventory"]})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, sys.argv[3])
