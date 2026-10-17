"""Owned inert planning sources; the sparse file is authenticated by metadata only."""
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

from cargo_audit import save
from secret_settings import ledger


def source_state(root):
    paths = [root / "owned.c", root / "scope.txt", root / "vendor/owned.scala",
             root.joinpath(*(["d"] * 80), "deep.c")]
    files = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    stat = (root / "oversized.c").stat()
    return {"fileHashes": files, "sparseMetadataOnly": {
        "size": stat.st_size, "modifiedNs": stat.st_mtime_ns, "inode": stat.st_ino}}


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "owned.c").write_text("// Owned inert metadata. Never executed.\n")
    deep = root.joinpath(*(["d"] * 80))
    deep.mkdir(parents=True)
    (deep / "deep.c").write_text("// Owned deep metadata. Never executed.\n")
    (root / "vendor").mkdir()
    (root / "vendor/owned.scala").write_text("// Owned explicit metadata. Never executed.\n")
    (root / "scope.txt").write_text("vendor/owned.scala\n")
    with (root / "oversized.c").open("wb") as file:
        file.truncate(512 * 1024 * 1024 + 1)
    (root / "cycle").symlink_to(root, target_is_directory=True)
    (root / "linked.c").symlink_to(root / "owned.c")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("")
    save(evidence, "source-before", source_state(root))


def inspect(root, evidence, stage):
    assert source_state(root) == json.loads((evidence / "source-before.json").read_text())
    runs = [(path.parent, json.loads(path.read_text()))
            for path in (root / ".kuzushi/v3/runs").glob("*/run.json")]
    partial = [(folder, run) for folder, run in runs if run["status"] == "partial"]
    assert len(partial) == 1
    folder, run = partial[0]
    assert run["tool"] == "full-mode:hunt"
    value = json.loads((folder / "result.json").read_text())
    assert value["status"] == "partial"
    data = value["data"]
    coverage = data["plan"]["coverage"]
    assert data["dryRun"] and not data["scanExecuted"] and data["chunksDispatched"] == 0
    assert coverage["enumeration"] == "filesystem" and not coverage["enumerationIncomplete"]
    assert coverage["inventory"]["enumeration_complete"] is True
    assert coverage["planningReadBytes"] == 0
    assert coverage["maxSourceBytes"] == 512 * 1024 * 1024
    assert len(coverage["omittedSources"]) == 1
    assert coverage["omittedSources"][0]["path"] == "oversized.c"
    assert "source byte planning limit" in coverage["omittedSources"][0]["reason"]
    assert "oversized.c" in coverage["inventory"]["truncated_files"]
    excluded = {row["path"] for row in coverage["excludedPaths"]}
    assert {"vendor", "cycle", "linked.c"} <= excluded
    files = {file["path"] for chunk in data["plan"]["chunks"] for file in chunk["files"]}
    assert files == {"owned.c", "/".join(["d"] * 80) + "/deep.c"}
    assert "oversized.c" not in files and "linked.c" not in files
    assert "partial; execution blocked" in value["output"]
    (evidence / "partial-replay.txt").write_text("replay " + folder.name)
    complete = [(folder, run) for folder, run in runs if run["status"] == "completed"]
    expected = int(stage != "partial")
    assert len(complete) == expected and len(runs) == 1 + expected
    if complete:
        folder, run = complete[0]
        assert run["tool"] == "full-mode:hunt"
        value = json.loads((folder / "result.json").read_text())
        data = value["data"]
        assert data["plan"]["coverage"]["enumeration"] == "explicit-scope"
        assert data["plan"]["coverage"]["omittedSources"] == []
        files = {file["path"] for chunk in data["plan"]["chunks"] for file in chunk["files"]}
        assert files == {"vendor/owned.scala"}
        assert data["dryRun"] and not data["scanExecuted"] and data["chunksDispatched"] == 0
        (evidence / "explicit-replay.txt").write_text("replay " + folder.name)
    assert not list((root / ".kuzushi/v3/campaigns").glob("**/queue.json"))
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
            assert table not in tables or db.execute("select count(*) from " + table).fetchone()[0] == 0
    if stage in ["exported", "restarted"]:
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert report["count"] == 0 and report["findings"] == []
    save(evidence, stage + "-check", {"partialPlanningRuns": 1, "explicitPlanningRuns": expected,
        "scanJobs": 0, "providerRequests": 0, "targetSourceExecuted": False,
        "smallSourceHashesUnchanged": True, "sparseFileMetadataUnchanged": True,
        "sparseContentNotAuthenticated": True})


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
