"""Bounded synthetic Review ledger and external writer. No model/source execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path


def source_state(root):
    names = ["README.md", "src/lib.rs", ".kuzushi/v3/runs/large-a/run.json", ".kuzushi/v3/runs/large-b/run.json"]
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}


def counts(root):
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        return {"observations": db.execute("select count(*) from finding_observations").fetchone()[0],
                "decisions": db.execute("select count(*) from review_decisions").fetchone()[0]}


def prepare(root, evidence):
    receipt = json.loads((root / "large-review-receipt.json").read_text())
    assert receipt["findingCount"] == 1000 and receipt["reviewed"] == 1000
    assert receipt["findingsAreSynthetic"] and receipt["commitMetadataIsSynthetic"]
    assert receipt["providerRequests"] == 0 and receipt["sourceExecuted"] is False
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "source-before.json").write_text(json.dumps(source_state(root), indent=2) + "\n")
    (evidence / "counts-before.json").write_text(json.dumps(counts(root), indent=2) + "\n")
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        last_id = db.execute("select coalesce(max(id), 0) from review_decisions").fetchone()[0]
    (evidence / "decision-id-before.json").write_text(json.dumps(last_id) + "\n")


def start_writer(root, evidence):
    executable = os.environ["KUZUSHI_LARGE_REVIEW_TEST_BIN"]
    env = dict(os.environ, KUZUSHI_LARGE_REVIEW_WRITER_ROOT=str(root), KUZUSHI_LARGE_REVIEW_WRITER_RECEIPT=str(evidence / "writer-receipt.json"))
    with (evidence / "writer.log").open("wb") as output:
        process = subprocess.Popen([executable, "--exact", "app::findings::show_aliases::refresh_findings::tests::large_ledger::write_bounded_large_review_fixture_decisions", "--nocapture"],
                                   env=env, stdout=output, stderr=subprocess.STDOUT)
    (evidence / "writer-process.json").write_text(json.dumps({"pid": process.pid, "executable": executable, "maximumDecisions": 6}) + "\n")


def verify(root, evidence):
    assert source_state(root) == json.loads((evidence / "source-before.json").read_text())
    writer = json.loads((evidence / "writer-receipt.json").read_text())
    assert writer["decisionsWritten"] == 6 and writer["providerRequests"] == 0
    before = json.loads((evidence / "counts-before.json").read_text())
    after = counts(root)
    assert after["observations"] == before["observations"] == 2000
    assert after["decisions"] == before["decisions"] + 6
    (evidence / "verification.json").write_text(json.dumps({"sourceUnchanged": True, "observationsUnchanged": True,
        "syntheticDecisionsAdded": 6, "sourceExecuted": False, "providerRequests": 0}, indent=2) + "\n")


def verify_read_only(root, evidence):
    assert source_state(root) == json.loads((evidence / "source-before.json").read_text())
    assert counts(root) == json.loads((evidence / "counts-before.json").read_text())
    (evidence / "verification.json").write_text(json.dumps({"sourceUnchanged": True,
        "ledgerUnchanged": True, "providerRequests": 0, "sourceExecuted": False}, indent=2) + "\n")


def verify_manual_decisions(root, evidence):
    assert source_state(root) == json.loads((evidence / "source-before.json").read_text())
    before = json.loads((evidence / "counts-before.json").read_text())
    last_id = json.loads((evidence / "decision-id-before.json").read_text())
    after = counts(root)
    assert after["observations"] == before["observations"]
    assert after["decisions"] == before["decisions"] + 8
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        rows = db.execute("select decision_verdict, rationale, author, identity_id, decision_read_watermark, decision_event_seq from review_decisions where id > ? order by id", (last_id,)).fetchall()
    labels = ["wide", "rail", "tall", "medium", "narrow", "tiny", "false positive", "restored"]
    verdicts = ["deferred", "confirmed", "deferred", "confirmed", "deferred", "confirmed", "rejected_false_positive", "confirmed"]
    assert [(row[0], row[1], row[2]) for row in rows] == list(zip(verdicts, [f"J103 {label}" for label in labels], ["human"] * 8))
    assert len({row[3] for row in rows}) == 1 and rows[0][3]
    assert all(row[4] is not None and row[4] < row[5] for row in rows)
    (evidence / "verification.json").write_text(json.dumps({"sourceUnchanged": True,
        "observationsUnchanged": True, "decisionsWritten": 8, "before": before, "after": after,
        "sameIdentity": rows[0][3], "explicitHumanDecisions": True,
        "providerRequests": 0, "sourceExecuted": False}, indent=2) + "\n")


def hold_projection(root, ready):
    with sqlite3.connect(root / ".kuzushi/v3/index.sqlite3", timeout=3) as db:
        db.execute("begin immediate")
        ready.write_text("held\n")
        time.sleep(2)
        db.rollback()


def start_contention(root, evidence):
    ready = evidence / f"projection-lock-{uuid.uuid4()}.ready"
    process = subprocess.Popen([sys.executable, "-B", __file__, "hold-projection", str(root), str(ready)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if ready.exists():
            return
        if process.poll() is not None:
            break
        time.sleep(0.01)
    process.kill()
    process.wait(timeout=1)
    raise RuntimeError("bounded projection lock did not start")


def record_filter_decision(root, evidence, verdict):
    executable = os.environ["KUZUSHI_NATIVE_BIN"]
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        rows = db.execute("select finding_json from finding_observations where title = ?",
                          ("Synthetic Review candidate 0000",)).fetchall()
    fingerprints = {json.loads(row[0])["fingerprint"] for row in rows}
    assert len(fingerprints) == 1
    result = subprocess.run([executable, "--target", str(root), "decision", fingerprints.pop(),
        "--verdict", verdict, "--reason", f"J104 {verdict}", "--json"],
        capture_output=True, text=True, timeout=30)
    (evidence / f"decision-{verdict}.json").write_text(result.stdout)
    (evidence / f"decision-{verdict}.stderr.txt").write_text(result.stderr)
    result.check_returncode()


def verify_filtered_review(root, evidence):
    assert source_state(root) == json.loads((evidence / "source-before.json").read_text())
    before = json.loads((evidence / "counts-before.json").read_text())
    last_id = json.loads((evidence / "decision-id-before.json").read_text())
    after = counts(root)
    assert after["observations"] == before["observations"] == 2000
    assert after["decisions"] == before["decisions"] + 2
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        rows = db.execute("select decision_verdict, rationale, author, identity_id from review_decisions where id > ? order by id",
                          (last_id,)).fetchall()
    assert [row[:3] for row in rows] == [("needs_review", "J104 needs_review", "human"),
                                        ("confirmed", "J104 confirmed", "human")]
    assert len({row[3] for row in rows}) == 1 and rows[0][3]
    (evidence / "verification.json").write_text(json.dumps({"sourceUnchanged": True,
        "observationsUnchanged": True, "decisionsWritten": 2, "before": before, "after": after,
        "sameIdentity": rows[0][3], "explicitHumanDecisions": True,
        "providerRequests": 0, "sourceExecuted": False}, indent=2) + "\n")


if __name__ == "__main__":
    action, target, output = sys.argv[1:]
    {"prepare": prepare, "start-writer": start_writer, "verify": verify, "verify-read-only": verify_read_only,
        "verify-manual-decisions": verify_manual_decisions, "hold-projection": hold_projection,
        "start-contention": start_contention,
        "mark-open": lambda root, evidence: record_filter_decision(root, evidence, "needs_review"),
        "mark-confirmed": lambda root, evidence: record_filter_decision(root, evidence, "confirmed"),
        "verify-filtered-review": verify_filtered_review}[action](Path(target).resolve(), Path(output).resolve())
