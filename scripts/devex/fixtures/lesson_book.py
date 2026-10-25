"""Two-page owned lesson book using real prepared dispatch and immutable context."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def execute(root, evidence, label, tool, value):
    path = evidence / (label + "-input.json")
    save(evidence, label + "-input", value)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", tool, "--input", "@" + str(path)], capture_output=True, text=True, timeout=30)
    (evidence / (label + "-stdout.json")).write_text(result.stdout)
    (evidence / (label + "-stderr.log")).write_text(result.stderr)
    assert result.returncode == 0, (tool, result.returncode, result.stderr)
    return json.loads(result.stdout)["data"]


def source_hashes(root):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.iterdir() if p.is_file()}


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    env = dict(os.environ, KUZUSHI_LESSON_BOOK_FIXTURE_OUT=str(root))
    result = subprocess.run([os.environ["KUZUSHI_LESSON_TEST_BIN"], "--exact", "--ignored",
        "app::lessons::tests::pagination::prepare_native_lesson_book_fixture", "--nocapture"],
        env=env, capture_output=True, text=True, timeout=30, check=True)
    (evidence / "preparation.log").write_text(result.stdout + result.stderr)
    fixture = json.loads((root / ".kuzushi/lesson-book-fixture.json").read_text())
    assert fixture["findingsAreSynthetic"] and fixture["providerRequests"] == 0
    save(evidence, "primary", fixture["primary"])
    active = next(path for path in root.rglob("threat-model.json") if "/objects/" not in str(path))
    save(evidence, "active-before", {"path": str(active), "sha256": hashlib.sha256(active.read_bytes()).hexdigest()})
    save(evidence, "source-before", source_hashes(root))
    (evidence / "title-suffix.txt").write_text(" updated")
    (evidence / "accept-reason.txt").write_text("Reviewed the exact updated lesson and its historical limits.")
    (evidence / "retire-reason.txt").write_text("Retire only the updated primary lesson after the copy checks.")
    inspect(root, evidence, "initial")


def book_rows(root, evidence, stage):
    pages = [execute(root, evidence, stage + "-page-" + str(offset),
             "findings:lessons", {"offset": offset}) for offset in [0, 50]]
    assert len(pages[0]["rows"]) == 50 and pages[0]["hasMore"]
    assert len(pages[1]["rows"]) == 10 and not pages[1]["hasMore"]
    rows = pages[0]["rows"] + pages[1]["rows"]
    assert len({row["lesson"]["id"] for row in rows}) == 60
    return rows


def inspect_copies(root, evidence, stage, primary):
    data = execute(root, evidence, stage + "-models", "threat-model:models", {})
    models = data.get("manifest", data)["models"]
    expected = 1 if stage == "initial" else (2 if stage in ["first-copy", "updated"] else 3)
    assert len(models) == expected, models
    primary_id = primary["lesson"]["id"]
    snapshots = []
    for index, model in enumerate(models[1:]):
        revision = model["revisions"][-1]
        reference = {"modelId": model["modelId"], "revisionId": revision["revisionId"], "sha256": revision["sha256"]}
        value = execute(root, evidence, stage + "-copy-" + str(index),
                        "threat-model:read", {"threatModelRef": reference})
        records = value["document"]["reviewedLessons"]
        assert len(records) == 1 and records[0]["id"] == primary_id
        assert records[0]["revision"] == (2 if index == 0 else 4), records
        accepted = primary["lesson"] if index == 0 else json.loads((evidence / "updated-accepted.json").read_text())
        assert records[0] == accepted
        usable = stage == "first-copy" or (stage == "second-copy" and index == 1)
        assert value["lessonState"]["usable"] == usable, value["lessonState"]
        snapshots.append({"reference": reference, "lessonRevision": records[0]["revision"], "usable": usable})
    return snapshots


def inspect(root, evidence, stage):
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    active = json.loads((evidence / "active-before.json").read_text())
    assert hashlib.sha256(Path(active["path"]).read_bytes()).hexdigest() == active["sha256"]
    primary = json.loads((evidence / "primary.json").read_text())
    rows = book_rows(root, evidence, stage)
    row = next(row for row in rows if row["lesson"]["id"] == primary["lesson"]["id"])
    expected = {"initial": ("accepted", 2), "first-copy": ("accepted", 2),
        "updated": ("draft", 3), "second-copy": ("accepted", 4),
        "retired": ("retired", 5), "restarted": ("retired", 5)}[stage]
    assert (row["lesson"]["state"], row["lesson"]["revision"]) == expected, row
    assert row["lesson"]["origin"] == primary["lesson"]["origin"]
    assert sum(other["lesson"]["state"] == "draft" for other in rows) == (60 if stage == "updated" else 59)
    if stage not in ["initial", "first-copy"]:
        assert row["lesson"]["content"]["title"] == "Book lesson 001 updated"
    if stage == "second-copy":
        save(evidence, "updated-accepted", row["lesson"])
    snapshots = inspect_copies(root, evidence, stage, primary)
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("pragma query_only=on")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 1
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 1
        for table in ["investigation_call_reservations", "investigation_work_attempts"]:
            if table in tables:
                assert db.execute("select count(*) from " + table).fetchone()[0] == 0
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    save(evidence, stage + "-check", {"lessons": 60, "primaryState": expected[0],
         "primaryRevision": expected[1], "contextCopies": snapshots, "observations": 1,
         "humanFindingDecisions": 1, "sourceUnchanged": True, "activeContextUnchanged": True,
         "providerRequests": 0, "sourceExecuted": False, "discoveryJobs": 0})


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence)
    else:
        inspect(root, evidence, stage)
