"""Owned compatibility planning and scope consumption. No inference or source execution."""
import hashlib
import json
import re
import sqlite3
import sys
import time
from pathlib import Path

SOURCES = ["loose.c", "src/owned.c", "other/large.c", "notes.txt", ".kuzushi/shards.toml"]


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES}


def seed(root, evidence, home):
    assert root == evidence / "fixture-target"
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    for name in ["src", "other", ".kuzushi"]:
        (root / name).mkdir(exist_ok=True)
    for name in ["loose.c", "src/owned.c"]:
        (root / name).write_text("// Owned scope fixture. Never executed.\n")
    (root / "other/large.c").write_text("// Owned unselected source prefix.\n" * 12_000)
    (root / "notes.txt").write_text("Labeled planning fixture; no completed scan.\n")
    (root / ".kuzushi/shards.toml").write_text('[shards.fixture]\npaths=["src","loose.c"]\n')
    (root / "src/cycle").symlink_to(root / "src", target_is_directory=True)
    (root / "linked.c").symlink_to(root / "other/large.c")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("")
    (evidence / "home.txt").write_text(str(home))
    save(evidence, "source-before", hashes(root))


def completed_results(root, tool):
    results = []
    for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
        run = json.loads(path.read_text())
        result = path.with_name("result.json")
        if run["tool"] == tool and result.exists():
            results.append((path.parent, run, json.loads(result.read_text())))
    return results


def verify(root, evidence, stage):
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    results = completed_results(root, "campaign:plan")
    expected = {"refused": 1, "planned": 2, "consumed": 2, "reused": 3, "restarted": 3}[stage]
    assert len(results) == expected
    refused = [(folder, value) for folder, run, value in results if "requires strategy=chunked" in value.get("output", "")]
    assert len(refused) == 1
    (evidence / "refusal-replay.txt").write_text("replay " + refused[0][0].name)
    assert not (root / ".kuzushi/v3/campaigns/standard/plan.json").exists()
    if stage != "refused":
        inspect_plan(root, evidence, results)
    if stage in ["consumed", "reused", "restarted"]:
        consumed = completed_results(root, "full-mode:hunt")
        assert len(consumed) == 1
        folder, run, value = consumed[0]
        assert run["status"] == value["status"] == "completed"
        data = value["data"]
        assert data["dryRun"] and not data["scanExecuted"] and data["chunksDispatched"] == 0
        assert {item["path"] for chunk in data["plan"]["chunks"] for item in chunk["files"]} == {"loose.c", "src/owned.c"}
        (evidence / "consumer-replay.txt").write_text("replay " + folder.name)
    if stage in ["reused", "restarted"]:
        reused = [folder for folder, _, value in results if "already has a plan" in value.get("output", "")]
        assert len(reused) == 1
        (evidence / "reuse-replay.txt").write_text("replay " + reused[0].name)
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    database = root / ".kuzushi/v3/index.sqlite3"
    if database.exists():
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
            tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            for table in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
                assert table not in tables or db.execute("select count(*) from " + table).fetchone()[0] == 0
    for path in (root / ".kuzushi/v3/workflow").glob("phase-attempts*.jsonl"):
        assert not path.read_text().strip(), "Local planning must not create Map or Scan evidence"
    save(evidence, stage + "-check", {"sourceUnchanged": True, "providerRequests": 0,
         "jobsStarted": 0, "targetSourceExecuted": False, "mapOrScanEvidenceCreated": False,
         "compatibilityPlanRuns": expected, "scopeConsumerIsDryRun": stage in ["consumed", "reused", "restarted"]})


def inspect_plan(root, evidence, results):
    planned = [(folder, value) for folder, run, value in results if run["status"] == "completed"]
    assert len(planned) == 1
    folder, value = planned[0]
    plan = value["data"]["plan"]
    assert plan == json.loads((root / ".kuzushi/v3/campaigns/bounded/plan.json").read_text())
    assert plan["jobCount"] == 1 and plan["tool"] == "full-mode:hunt"
    receipt = plan["scopeInventory"]
    assert receipt["enumerationComplete"] and receipt["truncatedFiles"] == 1
    artifact = root / receipt["path"]
    assert "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest() == receipt["sha256"]
    assert (root / plan["jobs"][0]["input"]["scopeFile"]).read_text() == "loose.c\nsrc/owned.c\n"
    assert "Compatibility draft only" in value["output"]
    assert "does not establish complete repository analysis" in value["output"]
    (evidence / "plan-replay.txt").write_text("replay " + folder.name)
    consumer = dict(plan["jobs"][0]["input"], dryRun=True, reuseCachedChunks=False)
    (evidence / "consumer-command.txt").write_text("run full-mode:hunt " + json.dumps(consumer))
    frozen = {"plan": hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest(), "inventory": receipt["sha256"]}
    before = evidence / "published-plan.json"
    if before.exists():
        assert json.loads(before.read_text()) == frozen
    else:
        save(evidence, "published-plan", frozen)


def wait(root, evidence, stage):
    deadline = time.monotonic() + 30
    while True:
        try:
            verify(root, evidence, stage)
            return
        except (AssertionError, FileNotFoundError, json.JSONDecodeError, sqlite3.OperationalError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def narrow_reader(root, evidence):
    verify(root, evidence, "planned")
    paths = sorted(evidence.glob("*-plan-page-*-40x12.txt"))
    paths += list(evidence.glob("*-plan-40x12.txt"))
    assert len(paths) == 7
    rows = {}
    total = None
    for path in paths:
        lines = path.read_text().splitlines()
        index, match = next((i, re.search(r"rows (\d+)-(\d+)/(\d+)", line))
                            for i, line in enumerate(lines) if re.search(r"rows (\d+)-(\d+)/(\d+)", line))
        start, end, count = map(int, match.groups())
        assert total in [None, count]
        total = count
        for number, line in zip(range(start, end + 1), lines[index + 1:index + 2 + end - start]):
            assert number not in rows or rows[number] == line, (path, number)
            rows[number] = line
    assert set(rows) == set(range(1, total + 1)), (sorted(rows), total)
    text = " ".join(rows[number].strip() for number in sorted(rows))
    assert "campaign:study" in text and "repository analysis" in text
    assert "No jobs started or investigation allowance approved." in text
    save(evidence, "narrow-reader-check", {"capturedRows":len(rows), "totalRows":total,
         "everyRowReachableByVisiblePageKeys":True, "limitationsAndStudyRouteRead":True})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif sys.argv[3] == "narrow":
        narrow_reader(root, evidence)
    else:
        wait(root, evidence, sys.argv[3])
