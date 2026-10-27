"""Owned reviewed-lesson journey. Real ledger and dispatch, no model or source execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from rejected_context import execute


def prepare(root, evidence):
    env = dict(os.environ, KUZUSHI_LESSON_FIXTURE_OUT=str(root))
    result = subprocess.run([os.environ["KUZUSHI_LESSON_TEST_BIN"], "--exact",
        "app::lessons::tests::fixture::prepare_native_reviewed_lesson_fixture", "--nocapture"],
        env=env, capture_output=True, text=True, timeout=30, check=True)
    (evidence / "preparation.log").write_text(result.stdout + result.stderr)
    record_prepared(root, evidence)


def record_prepared(root, evidence):
    receipt = json.loads((root / ".kuzushi/lesson-fixture.json").read_text())
    assert receipt["findingsAreSynthetic"] and receipt["providerRequests"] == 0
    (evidence / "source-before.sha256").write_text(hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest())
    active = root / ".kuzushi/v3/threat-model.json"
    if not active.exists():
        candidates = list(root.rglob("threat-model.json"))
        active = next(path for path in candidates if "/objects/" not in str(path))
    (evidence / "active-before.json").write_text(json.dumps({"path": str(active), "sha256": hashlib.sha256(active.read_bytes()).hexdigest()}))
    for name, text in {
        "title": "Greeting review lesson",
        "text": "Inspect recorded greeting evidence.\nUnicode café stays in the lesson field.",
        "applies": "Manual review of owned greeting source.",
        "limits": "Historical guidance only. Current source needs independent review.",
        "reason": "Reviewed the complete text, applicability and historical limits.",
        "retire": "Retire the labeled lesson after the context-copy experiment.",
        "retained": "Keep this unsubmitted note after copying context.\nUnicode café stays editable.",
    }.items():
        (evidence / (name + ".txt")).write_text(text)
    (evidence / "open.txt").write_text("open generation:" + str(receipt["findingId"]))
    verify(root, evidence, "empty")


def verify(root, evidence, stage):
    page = execute(root, Path(os.environ["HOME"]), evidence, "lessons-" + stage, "findings:lessons", {})
    rows = page["rows"]
    expected = {"empty": None, "replacement-choice": None, "draft-confirmation": None, "draft": "draft", "accept-confirmation": "draft",
        "accepted": "accepted", "copy-confirmation": "accepted", "copy": "accepted", "retained-copy": "accepted", "retired": "retired", "restart": "retired"}[stage]
    if expected is None:
        assert rows == []
    else:
        assert len(rows) == 1 and rows[0]["lesson"]["state"] == expected, rows
        record = rows[0]["lesson"]
        assert record["origin"]["finding"]["findingId"] == json.loads((root / ".kuzushi/lesson-fixture.json").read_text())["findingId"]
        assert record["origin"]["decision"]["decision"]["author"] == "human"
        assert record["content"]["text"] == (evidence / "text.txt").read_text()
    # SQLite may need WAL sidecars for reads. SQL writes remain prohibited.
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 1
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 1
        assert db.execute("select count(*) from rekey_edges").fetchone()[0] == 0
    active = json.loads((evidence / "active-before.json").read_text())
    assert hashlib.sha256(Path(active["path"]).read_bytes()).hexdigest() == active["sha256"]
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest() == (evidence / "source-before.sha256").read_text()
    catalog = execute(root, Path(os.environ["HOME"]), evidence, "models-" + stage, "threat-model:models", {})
    models = catalog.get("manifest", catalog).get("models", [])
    if stage in ["copy", "retained-copy", "retired", "restart"]:
        assert len(models) == 2, catalog
        copy = models[-1]
        revision = copy["revisions"][-1]
        reference = {"modelId": copy["modelId"], "revisionId": revision["revisionId"], "sha256": revision["sha256"]}
        data = execute(root, Path(os.environ["HOME"]), evidence, "copy-read-" + stage, "threat-model:read", {"threatModelRef": reference})
        assert len(data["document"]["reviewedLessons"]) == 1
        assert data["lessonState"]["usable"] == (stage in ["copy", "retained-copy"])
    else:
        assert len(models) == 1, catalog
    (evidence / (stage + "-check.json")).write_text(json.dumps({"stage": stage, "lessonState": expected, "lessonCount": len(rows),
        "observations": 1, "humanFindingDecisions": 1, "providerRequests": 0, "sourceExecuted": False,
        "sourceUnchanged": True, "activeContextUnchanged": True}, indent=2) + "\n")


if __name__ == "__main__":
    action, target, output = sys.argv[1:]
    root, evidence = Path(target).resolve(), Path(output).resolve()
    if action == "prepare":
        prepare(root, evidence)
    else:
        verify(root, evidence, action)
