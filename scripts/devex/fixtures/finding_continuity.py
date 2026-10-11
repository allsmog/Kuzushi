"""Owned synthetic ledger replacement. No scanner, model or source execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def run_fixture(root, evidence, name):
    binary = os.environ["KUZUSHI_CONTINUITY_TEST_BIN"]
    command = [binary, "--exact", "app::findings::paging::continuity_tests::" + name, "--ignored", "--nocapture"]
    result = subprocess.run(command, env={**os.environ, "KUZUSHI_CONTINUITY_FIXTURE_OUT":str(root)},
                            capture_output=True, text=True, timeout=60, check=True)
    (evidence / (name + ".log")).write_text(result.stdout + result.stderr)


def receipt(root):
    return json.loads((root / "continuity-fixture.json").read_text())


def read_page(root, evidence, stage, anchor):
    command = [os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root), "run", "findings:list", "--input",
               json.dumps({"anchor":anchor,"order":"confidence","limit":500})]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=True)
    (evidence / (stage + "-page.stdout.json")).write_text(result.stdout)
    (evidence / (stage + "-page.stderr.txt")).write_text(result.stderr)
    data = json.loads(result.stdout)["data"]
    assert data["page"]["offset"] == 500 and data["page"]["total"] == 800
    return data


def prepare(root, evidence):
    run_fixture(root, evidence, "prepare_native_continuity_fixture")
    data = receipt(root)
    assert data["findingCount"] == 800 and data["findingsAreSynthetic"]
    (evidence / "open.txt").write_text("open " + data["alias"])
    (evidence / "source-before.sha256").write_text(hashlib.sha256((root / "lib.rs").read_bytes()).hexdigest())
    page = read_page(root, evidence, "before", "generation:" + str(data["beforeId"]))
    index = next(index for index,row in enumerate(page["findings"]) if row["fingerprint"] == data["fingerprint"])
    assert page["page"]["anchors"][index] == "generation:" + str(data["beforeId"])
    (evidence / "continuity-anchor.txt").write_text(page["page"]["continuityAnchors"][index])


def replace(root, evidence):
    run_fixture(root, evidence, "write_native_continuity_replacement")
    data = receipt(root)
    assert data["afterId"] != data["beforeId"]
    current = hashlib.sha256((root / "lib.rs").read_bytes()).hexdigest()
    assert current != (evidence / "source-before.sha256").read_text()
    (evidence / "source-after.sha256").write_text(current)
    page = read_page(root, evidence, "after", (evidence / "continuity-anchor.txt").read_text())
    index = next(index for index,row in enumerate(page["findings"]) if row["fingerprint"] == data["fingerprint"])
    assert page["page"]["anchors"][index] == "generation:" + str(data["afterId"])
    verify(root, evidence, "replaced", 1)


def verify(root, evidence, stage, expected_decisions):
    data = receipt(root)
    assert hashlib.sha256((root / "lib.rs").read_bytes()).hexdigest() == (evidence / "source-after.sha256").read_text()
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 801
        rows = db.execute("select finding_id, decision_verdict, rationale, author, decision_read_watermark from review_decisions order by id").fetchall()
        assert len(rows) == expected_decisions, rows
        assert rows[0][0] == data["beforeId"]
        if expected_decisions == 2:
            assert rows[-1][0] == data["afterId"]
            assert rows[-1][1:4] == ("deferred", "J145 current observation deliberately deferred", "human")
            assert rows[-1][4] > rows[0][4]
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts"]:
            if table in tables: assert db.execute("select count(*) from " + table).fetchone()[0] == 0
    (evidence / (stage + "-check.json")).write_text(json.dumps({"findingsAreSynthetic":True,
        "logicalFindings":800,"observations":801,"humanDecisions":expected_decisions,
        "providerRequests":0,"scannerJobs":0,"sourceExecuted":False,"sourceAfterPlannedEditUnchanged":True},indent=2)+"\n")


root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
if stage == "prepare": prepare(root, evidence)
elif stage == "replace": replace(root, evidence)
else: verify(root, evidence, stage, 2)
