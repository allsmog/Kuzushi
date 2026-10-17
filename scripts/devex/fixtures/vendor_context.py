"""Owned vendor evidence and local packet consumption, without provider work."""
import json
import sqlite3
import sys
import time
from pathlib import Path

from cargo_audit import hashes, save
from secret_settings import ledger


def scope_path(root):
    return root / ".kuzushi/vendor-assessment/scope.json"


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "owned-evidence.txt").write_text("a" * 255999 + "é" + " tail" * 50)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("")
    save(evidence, "source-before", hashes(root))


def inspect(root, evidence, stage):
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    runs = [(path.parent, json.loads(path.read_text()))
            for path in (root / ".kuzushi/v3/runs").glob("*/run.json")]
    counts = {"set": 1, "inspect": 2, "failed": 3, "attached": 4, "referenced": 5,
              "packet": 6, "cleared": 7, "exported": 7, "restarted": 7}
    assert len(runs) == counts[stage]
    for folder, run in runs:
        assert run["tool"] in {"vendor-assessment:scope", "vendor-assessment:attach", "vendor-assessment:prompts"}
        assert run["status"] in {"completed", "failed"}
        result = json.loads((folder / "result.json").read_text())
        assert result["status"] == run["status"]
    state_bytes = scope_path(root).read_bytes()
    scope = json.loads(state_bytes)
    if stage == "set":
        (evidence / "saved-scope.json").write_bytes(state_bytes)
    if stage in {"set", "inspect", "failed"}:
        assert scope["profile"] == "operator-profile" and scope["vendorName"] == "Owned vendor"
        assert state_bytes == (evidence / "saved-scope.json").read_bytes()
    if stage == "inspect":
        latest = max((folder for folder, run in runs), key=lambda folder: folder.stat().st_mtime_ns)
        (evidence / "scope-replay.txt").write_text("replay " + latest.name)
    if stage == "failed":
        failed = [(folder, run) for folder, run in runs if run["status"] == "failed"]
        assert len(failed) == 1 and failed[0][1]["tool"] == "vendor-assessment:attach"
    if stage in {"attached", "referenced", "packet"}:
        doc = scope["documents"][0]
        assert doc["textTruncated"] and doc["capturedBytes"] == doc["storedTextBytes"] == 255999
        assert doc["sourceBytes"] == (root / "owned-evidence.txt").stat().st_size
        assert doc["sourceDigest"] == "sha256:" + json.loads((evidence / "source-before.json").read_text())["owned-evidence.txt"]
        assert "partial" in " ".join(doc["parseWarnings"])
        assert doc["text"] == "a" * 255999 and scope["profile"] == "operator-profile"
        attached = [(folder, json.loads((folder / "result.json").read_text()))
                    for folder, run in runs if run["tool"] == "vendor-assessment:attach" and run["status"] == "completed"]
        captured = next(folder for folder, value in attached if value["data"]["document"]["textTruncated"])
        (evidence / "capture-replay.txt").write_text("replay " + captured.name)
        if stage in {"referenced", "packet"}:
            ref = scope["documents"][1]
            assert ref["sourceBytes"] is None and ref["sourceDigest"] is None and ref["text"] == ""
            assert ref["status"] == "referenced" and "does not fetch" in " ".join(ref["parseWarnings"])
            referenced = next(folder for folder, value in attached if value["data"]["document"]["status"] == "referenced")
            (evidence / "reference-replay.txt").write_text("replay " + referenced.name)
    packet = root / ".kuzushi/vendor-assessment/runs/owned-packet/prompts"
    if stage == "packet":
        overview = (packet / "overview.md").read_text()
        parsed = json.loads(overview.split("Scope:\n", 1)[1])
        assert parsed == scope and len(list(packet.glob("*.md"))) == 3
        (evidence / "packet-scope.json").write_bytes(state_bytes)
        save(evidence, "packet-before", hashes(packet))
    if stage in {"cleared", "exported", "restarted"}:
        assert scope["documents"] == [] and scope["vendorName"] == "" and scope["profile"] == "enterprise-ai"
        assert hashes(packet) == json.loads((evidence / "packet-before.json").read_text())
        assert json.loads((packet / "overview.md").read_text().split("Scope:\n", 1)[1]) == json.loads((evidence / "packet-scope.json").read_text())
    assert not list((root / ".kuzushi/v3/campaigns").glob("**/queue.json"))
    assert all(path.stat().st_size == 0 for path in (root / ".kuzushi").rglob("phase-attempts*.jsonl"))
    assert not list((root / ".kuzushi/threat-models").glob("revisions/**/*"))
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
            assert table not in tables or db.execute("select count(*) from " + table).fetchone()[0] == 0
    if stage in {"exported", "restarted"}:
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert report["count"] == 0 and report["findings"] == []
    save(evidence, stage + "-check", {"auxiliaryRuns": len(runs), "scanJobs": 0,
        "providerRequests": 0, "sourceUnchanged": True, "targetSourceExecuted": False,
        "repositoryPhaseAttempts": 0, "priorPacketRetained": stage in {"cleared", "exported", "restarted"}})


def wait(root, evidence, stage):
    deadline = time.monotonic() + 25
    while True:
        try:
            inspect(root, evidence, stage)
            return
        except (AssertionError, FileNotFoundError, json.JSONDecodeError, sqlite3.OperationalError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        wait(root, evidence, stage)
