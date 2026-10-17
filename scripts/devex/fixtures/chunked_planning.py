"""Owned inert source qualifies chunk planning and refusal, without model work."""
import json
import sqlite3
import sys
import time
from pathlib import Path

from cargo_audit import hashes, save
from secret_settings import ledger


def prepare(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "owned.c").write_text("// Owned inert metadata. Never executed.\n" * 800)
    (root / "other.c").write_text("// Other owned inert metadata. Never executed.\n" * 800)
    (root / "empty-scope.txt").write_text("\n")
    outside = evidence / "outside-owned.c"
    outside.write_text("// Owned outside metadata. No confidential data. Never executed.\n")
    (root / "outside-scope.txt").write_text(str(outside) + "\n")
    (root / "README.md").write_text("# Owned chunk planning fixture\nComment-only source. No program or vulnerability is executed.\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("")
    (evidence / "home.txt").write_text(str(home))
    save(evidence, "source-before", hashes(root))


def inspect(root, evidence, stage):
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    home = Path((evidence / "home.txt").read_text())
    settings = json.loads((home / ".kuzushi/v3/options.json").read_text())
    assert settings["bindings"]["global/tool/full-mode:hunt"]["reuseCachedChunks"] is False
    runs = [(p.parent, json.loads(p.read_text()))
            for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
    if stage == "options":
        assert not runs
        save(evidence, "options-check", {"toolRuns": 0, "cacheReuse": False})
        return
    completed = [(folder, run) for folder, run in runs if run["tool"] == "full-mode:hunt" and run["status"] == "completed"]
    assert len(completed) == 1
    folder, run = completed[0]
    plan_run_id = folder.name
    result = json.loads((folder / "result.json").read_text())
    value = result["data"]
    assert value["dryRun"] and not value["scanExecuted"] and not value["reuseCachedChunks"]
    assert value["selection"]["chunkIds"] == [1] and value["selection"]["chunks"] == 1
    assert len(value["plan"]["chunks"]) > 1
    assert value["summary"]["chunks"] == 1 and not value["strictDollarCeiling"]
    assert value["chunksDispatched"] == 0 and value["findings"] == []
    assert "Planning only" in result["output"] and "Dollar estimate: uncertain" in result["output"]
    failed = [(folder, run) for folder, run in runs if run["tool"] == "full-mode:hunt" and run["status"] == "failed"]
    expected = {"planned": 0, "empty": 1, "unknown": 2, "scope-empty": 3, "outside": 4, "blocked": 4, "exported": 4, "restarted": 4}[stage]
    assert len(failed) == expected
    if failed:
        outputs = [json.loads((folder / "result.json").read_text())["output"] for folder, _ in failed]
        assert any("failedChunkIds is empty" in text for text in outputs)
        if expected >= 2:
            assert any("absent from this plan" in text for text in outputs)
        if expected >= 3:
            assert any("scopeFile is empty" in text for text in outputs)
        if expected == 4:
            assert any("invalid scoped source path" in text for text in outputs)
    blocked = []
    for folder, record in runs:
        if record["tool"] == "agentic-sast:scan":
            assert record["status"] == "blocked"
            refused = json.loads((folder / "result.json").read_text())
            assert refused["status"] == "blocked" and "cannot honor scanScopeRef" in refused["output"]
            blocked.append(folder.name)
        else:
            assert record["tool"] == "full-mode:hunt"
    if stage in ["blocked", "exported", "restarted"]:
        assert len(blocked) == 1
        (evidence / "blocked-replay.txt").write_text("replay " + blocked[0])
    if stage in ["exported", "restarted"]:
        pages = " ".join(" ".join(p.read_text().split()) for p in sorted(evidence.glob("*planning-reading-40x12*.txt")))
        for term in ["Cache reuse: disabled", "Dollar estimate: uncertain", "require separate approval"]:
            assert term in pages, "Narrow reader did not reach: " + term
    assert not list((root / ".kuzushi/v3/campaigns").glob("**/queue.json"))
    with ledger(root, evidence) as db:
        tables = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
        for table in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
            assert table not in tables or db.execute("select count(*) from " + table).fetchone()[0] == 0
    if stage in ["exported", "restarted"]:
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert report["count"] == 0 and report["findings"] == []
    (evidence / "plan-replay.txt").write_text("replay " + plan_run_id)
    save(evidence, stage + "-check", {"planningRuns": 1, "failedRetryRuns": expected,
        "selectedChunkIds": [1], "scanJobs": 0, "liveProviderRequests": 0,
        "targetSourceExecuted": False, "sourceUnchanged": True})


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
    if stage == "prepare":
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    else:
        wait(root, evidence, stage)
