"""Owned legacy-context hints. No configured model, credentials or source execution."""
import hashlib
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path


def save(folder, name, value):
    (folder / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source_hashes(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*") if not p.is_symlink() and p.is_file()
        and p.relative_to(root).parts[0] != ".kuzushi"}


def prepare(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "src").mkdir(exist_ok=True)
    (root / "src/owned.rs").write_text("// Owned parser response size limits. Never executed.\n")
    (root / "loose.md").write_text("Owned parser response size documentation.\n")
    (root / "large.rs").write_text("// Owned prefix fixture. Never executed.\n" * 10000)
    outside = evidence / "outside"
    outside.mkdir(exist_ok=True)
    (outside / "owned.rs").write_text("OWNED_OUTSIDE_MARKER\n")
    (root / "outside.rs").symlink_to(outside / "owned.rs")
    (root / "cycle").symlink_to(root, target_is_directory=True)
    state = root / ".kuzushi"
    state.mkdir(exist_ok=True)
    document = {"version":"2.0","methodology":"STRIDE","title":"Owned context hints fixture",
        "dfd":{"nodes":[{"id":"reader","name":"Owned reader " + "context label " * 1000,"type":"process","trustZone":"owned","description":"Reads supplied source"}],"flows":[],"trustBoundaries":[]},
        "threats":[{"id":"T1","title":"Owned parser resource question","targetElementIds":["reader"] * 40,"affectedFiles":["src/owned.rs","loose.md"]}]}
    (state / "threat-model.json").write_text(json.dumps(document, indent=2) + "\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("# Owned runtime-free fixture. No model or credentials.\n")
    save(evidence, "before", {"source":source_hashes(root),"modelSha256":hashlib.sha256((state / "threat-model.json").read_bytes()).hexdigest(),
        "configSha256":hashlib.sha256(config.read_bytes()).hexdigest(),"home":str(home)})


def verify(root, evidence, stage):
    state = root / ".kuzushi"
    before = json.loads((evidence / "before.json").read_text())
    assert source_hashes(root) == before["source"]
    config = Path(before["home"]) / ".kuzushi/v3/config.toml"
    assert hashlib.sha256(config.read_bytes()).hexdigest() == before["configSha256"]
    artifact = state / "threat-leads.json"
    expected = {"built":(1,"partial"),"stale-read":(2,"partial"),"repaired":(3,"partial"),
        "failed":(4,"failed"),"saved":(5,"partial"),"legacy-read":(6,"partial"),
        "restarted-state":(7,"failed"),"restarted":(8,"failed")}
    count, status = expected[stage]
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        runs = [json.loads(p.read_text()) for p in (state / "v3/runs").glob("*/run.json")]
        if len(runs) == count and all(row["status"] != "running" for row in runs):
            break
        time.sleep(0.05)
    assert len(runs) == count and all(row["status"] != "running" for row in runs), runs
    latest_id = (state / "v3/latest").read_text().strip()
    latest = next(row for row in runs if row["runId"] == latest_id)
    assert latest["status"] == status, latest
    if stage == "built":
        value = json.loads(artifact.read_text())
        assert value["leadCount"] == 1 and value["sourceCoverage"]["status"] == "partial"
        assert value["sourceCoverage"]["truncatedSourceFiles"] == 1
        assert value["sourceCoverage"]["completeRepositoryCoverage"] is False
        projection = value["sourceCoverage"]["contextProjection"]
        assert projection["omittedValues"] == 8 and projection["duplicateReferences"] == 31
        assert projection["truncatedTextFields"] == 1
        assert len(value["leads"][0]["linkedNodes"]) == 1
        assert len(value["leads"][0]["linkedNodes"][0]["name"].encode()) <= 4096
        assert projection["retainedCardBytes"] <= projection["maxRetainedCardBytes"]
        assert value["sources"]["threatModelSha256"] == "sha256:" + before["modelSha256"]
        candidates = {row["path"]: row for row in value["leads"][0]["candidateFiles"]}
        assert candidates["loose.md"]["classification"] == "documentation"
        assert "src/owned.rs" in candidates and "outside.rs" not in candidates
        assert "OWNED_OUTSIDE_MARKER" not in artifact.read_text()
        for name in ["threat-leads.json", "threat-leads.md"]:
            shutil.copyfile(state / name, evidence / ("produced-" + name))
    if stage == "stale-read":
        result = json.loads((state / "v3/runs" / latest_id / "result.json").read_text())
        assert result["summaryPublication"]["status"] == "stale", result
        assert all(row["label"] != "threat-leads-summary" for row in result["artifacts"])
        assert (state / "threat-leads.md").read_text() == "OWNED_STALE_SUMMARY\n"
    if stage == "repaired":
        assert (state / "threat-leads.md").read_bytes() == (evidence / "produced-threat-leads.md").read_bytes()
        assert not (state / "threat-model.json").exists()
    if stage in ["stale-read", "repaired", "failed", "saved"]:
        assert artifact.read_bytes() == (evidence / "produced-threat-leads.json").read_bytes()
    database = state / "v3/index.sqlite3"
    if database.is_file():
        with sqlite3.connect(database.as_uri() + "?mode=rw", uri=True) as db:
            db.execute("pragma query_only=on")
            tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            for table in ["finding_observations", "investigation_call_reservations", "investigation_work_attempts"]:
                if table in tables:
                    assert db.execute("select count(*) from " + table).fetchone()[0] == 0
    assert not (state / "v3/campaigns").exists()
    attempts = state / "v3/workflow/phase-attempts.jsonl"
    assert not attempts.exists() or not attempts.read_text().strip()
    assert all(row.get("model") is None and not row.get("phase") for row in runs)
    save(evidence, stage + "-check", {"sourceUnchanged":True,"sourceExecuted":False,"liveProviderRequests":0,
        "newCampaigns":0,"primaryAttempts":0,"findingObservations":0,"runModels":[row.get("model") for row in runs],
        "completedToolAttempts":len(runs),"latestOutcome":latest["status"]})


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    state = root / ".kuzushi"
    if stage == "prepare":
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "remove-context":
        (state / "threat-model.json").rename(evidence / "removed-context.json")
    elif stage == "stale":
        (state / "threat-leads.md").write_text("OWNED_STALE_SUMMARY\n")
    elif stage == "legacy":
        (state / "threat-leads.json").write_text(json.dumps({"leadCount":0,"leads":[]}) + "\n")
        (state / "threat-leads.md").unlink()
    elif stage == "invalid":
        (state / "threat-leads.json").write_text("{}\n")
    else:
        verify(root, evidence, stage)
