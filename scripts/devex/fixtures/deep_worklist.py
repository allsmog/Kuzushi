"""Owned bounded deep-ranking fixture. No model, graph build or source execution."""
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path


def save(folder, name, value):
    (folder / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source_hashes(root):
    return {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*") if p.is_file() and not p.is_symlink()
        and p.relative_to(root).parts[0] not in [".kuzushi", ".git"]}


def prepare(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    text = "// Owned parser packet length metadata. Never compiled or executed.\n"
    (root / "owned.c").write_text(text)
    (root / "large.c").write_text(text * 2000)
    (root / "README.md").write_text("Owned advisory ranking fixture. No finding claims.\n")
    (root / "tests").mkdir()
    (root / "tests/excluded.c").write_text(text)
    deep = root
    for _ in range(80):
        deep = deep / "d"
        deep.mkdir()
    (deep / "deep.c").write_text(text)
    outside = evidence / "outside"
    outside.mkdir()
    (outside / "outside.c").write_text(text)
    (root / "outside.c").symlink_to(outside / "outside.c")
    (root / "cycle").symlink_to(root, target_is_directory=True)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("# Owned runtime-free ranking. No model or credentials.\n")
    save(evidence,"before",{"source":source_hashes(root),"home":str(home),"configHash":hashlib.sha256(config.read_bytes()).hexdigest()})


def verify(root, evidence, stage):
    before = json.loads((evidence / "before.json").read_text())
    assert source_hashes(root) == before["source"]
    config = Path(before["home"]) / ".kuzushi/v3/config.toml"
    assert hashlib.sha256(config.read_bytes()).hexdigest() == before["configHash"]
    state = root / ".kuzushi/v3"
    expected = {"deep":1,"default":2,"deep-again":3,"restarted":3}[stage]
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        runs = [json.loads(p.read_text()) for p in (state / "runs").glob("*/run.json")]
        if len(runs) == expected and all(row["status"] != "running" for row in runs):
            break
        time.sleep(0.05)
    assert len(runs) == expected and all(row["status"] != "running" for row in runs), runs
    current = (state / "latest").read_text().strip()
    result = json.loads((state / "runs" / current / "result.json").read_text())
    if stage == "default":
        assert result["data"]["systemsInspection"] is None
        assert result["data"]["contributors"]["systemsHunt"] == "notRequested"
    else:
        assert result["status"] == "partial"
        data = result["data"]
        receipt = data["systemsInspection"]
        assert receipt["status"] == "partial" and receipt["completeRepositoryCoverage"] is False
        assert receipt["truncatedSourceFiles"] == receipt["evidenceLimitedFiles"] == 1
        assert receipt["maxSourceFiles"] == 2000 and receipt["maxFileBytes"] == 16384
        assert receipt["inspectedSourceBytes"] <= 16777216
        assert data["rankedTotal"] == len(data["rows"]) == 3, data
        assert all(row["path"] != "tests/excluded.c" and row["path"] != "outside.c" for row in data["rows"])
        assert any(row["path"].endswith("deep.c") for row in data["rows"])
        assert data["contributors"]["systemsHunt"].get("degraded")
    assert all(row.get("model") is None and not row.get("phase") for row in runs)
    for name in ["cpg-rs", "threat-model.json"]:
        assert not (root / ".kuzushi" / name).exists()
    assert not (state / "campaigns").exists()
    attempts = state / "workflow/phase-attempts.jsonl"
    assert not attempts.exists() or not attempts.read_text().strip()
    database = state / "index.sqlite3"
    if database.is_file():
        with sqlite3.connect(database.as_uri() + "?mode=rw",uri=True) as db:
            db.execute("pragma query_only=on")
            tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            for table in ["finding_observations", "investigation_call_reservations", "investigation_work_attempts"]:
                if table in tables:
                    assert db.execute("select count(*) from " + table).fetchone()[0] == 0
    save(evidence,stage+"-check",{"sourceUnchanged":True,"configUnchanged":True,"liveProviderRequests":0,"newScanJobs":0,
        "findingObservations":0,"primaryAttempts":0,"models":[row.get("model") for row in runs],"toolAttempts":len(runs)})


if __name__ == "__main__":
    root,evidence,stage=Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
    if stage=="prepare":
        prepare(root,evidence,Path(sys.argv[4]).resolve())
    else:
        verify(root,evidence,stage)
