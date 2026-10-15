"""Owned accepted lesson and context projection. No provider or source execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from rejected_context import execute


def save(output, name, value):
    (output / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def prepare(root, output):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    env = dict(os.environ, KUZUSHI_LESSON_FIXTURE_OUT=str(root))
    result = subprocess.run([env["KUZUSHI_LESSON_TEST_BIN"], "--exact",
        "app::lessons::tests::fixture::prepare_native_reviewed_lesson_fixture", "--nocapture"],
        env=env, capture_output=True, text=True, timeout=30, check=True)
    (output / "fixture-prepare.log").write_text(result.stdout + result.stderr)
    fixture = json.loads((root / ".kuzushi/lesson-fixture.json").read_text())
    assert fixture["findingsAreSynthetic"] and fixture["providerRequests"] == 0
    home = Path(env["HOME"])
    content = {"title": "Owned historical review lesson",
        "text": "Review owned historical context. " * 70 + "OMITTED_LESSON_TAIL",
        "applicability": "Owned static review example only.",
        "limitations": "Scripted synthetic acceptance. No vulnerability or current-source verdict."}
    draft = execute(root, home, output, "lesson-draft", "findings:lesson-save",
        {"findingId": fixture["findingId"], "content": content})
    accepted = execute(root, home, output, "lesson-accepted", "findings:lesson-review",
        {"lessonRef": draft["lessonRef"], "state": "accepted",
         "note": "Scripted owned fixture acceptance solely to inspect the projection."})
    copy = execute(root, home, output, "context-copy", "threat-model:reuse-lessons",
        {"threatModelRef": fixture["baseRef"], "lessons": [accepted["lessonRef"]],
         "label": "Owned scanner preview context"})
    save(output, "expected", {"reference": copy["modelRef"], "baseReference": fixture["baseRef"],
        "lessonReference": accepted["lessonRef"], "sourceSha256": hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest()})
    inspect(root, output, "prepared")


def inspect(root, output, stage):
    expected = json.loads((output / "expected.json").read_text())
    home = Path(os.environ["HOME"])
    data = execute(root, home, output, "context-read-" + stage, "threat-model:read",
                   {"threatModelRef": expected["reference"]})
    preview = data["scannerContextPreview"]
    assert preview["schemaVersion"] == 1
    assert preview["sha256"] == "sha256:" + hashlib.sha256(preview["text"].encode()).hexdigest()
    assert "Owned historical review lesson" in preview["text"]
    assert "OMITTED_LESSON_TAIL" not in preview["text"]
    assert "OMITTED_LESSON_TAIL" in json.dumps(data["document"])
    assert any("first 2048" in row for row in preview["omissions"])
    assert data["lessonState"]["usable"] is True
    catalog = execute(root, home, output, "catalog-" + stage, "threat-model:models", {})
    assert catalog.get("manifest", catalog)["active"] == expected["baseReference"]
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest() == expected["sourceSha256"]
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("pragma query_only=on")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for name in ["investigation_call_reservations", "investigation_work_attempts"]:
            assert name not in tables or db.execute("select count(*) from " + name).fetchone()[0] == 0
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 1
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 1
    for name in ["phase-attempts.jsonl", "phase-attempts.v2.jsonl"]:
        path = root / ".kuzushi/workflow" / name
        assert not path.exists() or not path.read_text().strip()
    save(output, stage + "-check", {"sourceUnchanged": True, "sourceExecuted": False,
        "providerRequests": 0, "discoveryJobs": 0, "phaseAttempts": 0,
        "syntheticObservationCount": 1, "scriptedFindingDecisions": 1,
        "lessonTailRetainedInDocument": True, "lessonTailOmittedInProjection": True,
        "projectionHash": preview["sha256"], "operatorVisualApproval": False})


root, output, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
if stage == "prepare":
    prepare(root, output)
else:
    inspect(root, output, stage)
