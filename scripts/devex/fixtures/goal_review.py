"""Labeled policy observations exercise priorities, never vulnerability validity."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from investigation_brief import native, save
from secret_settings import ledger


def page(root, evidence, name):
    return native(root, evidence, name, "findings:goals", {})["data"]


def seed(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    test_bin = Path(os.environ["KUZUSHI_DEVEX_GOAL_FIXTURE_TEST_BIN"]).resolve()
    result = subprocess.run([str(test_bin), "--exact", "app::goal_review::tests::prepare_native_goal_review_fixture", "--nocapture"],
        env=dict(os.environ, KUZUSHI_GOAL_FIXTURE_OUT=str(root)), capture_output=True, text=True, timeout=35)
    (evidence / "fixture-seed.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0 and "1 passed" in result.stdout, result.stdout
    first = page(root, evidence, "initial-goals")
    assert first["total"] == 3 and first["brief"]["reference"]["revision"] == 1
    save(evidence, "first-brief", first["brief"]["reference"])
    save(evidence, "source-before", {"note.txt": hashlib.sha256((root / "note.txt").read_bytes()).hexdigest()})
    (evidence / "reason.txt").write_text("Owner policy matches the reviewed goal.\n東京 reason remains separate from validity.")
    save(evidence, "fixture-executable", {"path": str(test_bin), "sha256": hashlib.sha256(test_bin.read_bytes()).hexdigest(), "findingsAreSynthetic": True, "sourceExecuted": False})


def conflict(root, evidence):
    current = page(root, evidence, "before-conflict")
    row = current["rows"][0]
    native(root, evidence, "other-assessment", "findings:goal-assess", {
        "briefRef": current["brief"]["reference"], "basis": row["basis"], "expectedRevision": row["assessment"]["revision"],
        "relevance": "uncertain", "reason": "A second operator retains uncertainty for this policy example"})


def revised(root, evidence):
    current = page(root, evidence, "before-brief-revision")
    assert any(row["assessment"] and row["assessment"]["relevance"] == "cleared" for row in current["rows"])
    native(root, evidence, "new-brief", "campaign:brief", {"mode": "save", "expectedRevision": 1,
        "text": "Goal\nReview package ownership in this second brief. Previous priorities remain historical."})


def verify(root, evidence):
    current = page(root, evidence, "verified-current-goals")
    assert current["brief"]["reference"]["revision"] == 2
    assert all(row["assessment"] is None for row in current["rows"])
    old_ref = json.loads((evidence / "first-brief.json").read_text())
    old = native(root, evidence, "verified-old-goals", "findings:goals", {"briefRef": old_ref})["data"]
    selected = [row for row in old["rows"] if row["assessment"] is not None]
    assert len(selected) == 1 and selected[0]["assessment"]["relevance"] == "cleared"
    history = native(root, evidence, "verified-history", "findings:goals", {"findingId": selected[0]["basis"]["findingId"]})["data"]["history"]
    assert [row["relevance"] for row in history] == ["direct", "uncertain", "related", "cleared"]
    assert all(row["briefRef"] == old_ref for row in history)
    assert hashlib.sha256((root / "note.txt").read_bytes()).hexdigest() == json.loads((evidence / "source-before.json").read_text())["note.txt"]
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
            for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]}
    assert counts["finding_observations"] == 3 and all(counts[name] == 0 for name in counts if name != "finding_observations"), counts
    save(evidence, "verified", {"counts": counts, "historyRevisions": len(history), "sourceUnchanged": True, "providerRequests": 0, "sourceExecuted": False})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    {"seed": seed, "conflict": conflict, "revised": revised, "verify": verify}[sys.argv[3]](root, evidence)
