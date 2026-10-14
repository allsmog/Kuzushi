"""Owned source-change and report metadata audit; no scanner or model work."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def native(root, evidence, label, tool, value, succeeds=True):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root), "run", tool, "--input", json.dumps(value)], capture_output=True, text=True, timeout=30)
    (evidence / (label + ".stdout.json")).write_text(result.stdout)
    (evidence / (label + ".stderr.txt")).write_text(result.stderr)
    assert (result.returncode == 0) == succeeds, result.stderr
    return json.loads(result.stdout) if succeeds else result.stderr


def seed(root, evidence):
    result = subprocess.run([os.environ["KUZUSHI_SARIF_TEST_BIN"], "--exact", "report::confirmed_sarif::metadata::tests::dispatch::prepare_native_confirmed_sarif_fixture", "--ignored", "--nocapture"], env={**os.environ, "KUZUSHI_SARIF_FIXTURE_OUT":str(root)}, capture_output=True, text=True, timeout=30, check=True)
    (evidence / "preparation.log").write_text(result.stdout + result.stderr)
    receipt = json.loads((root / ".kuzushi/sarif-fixture.json").read_text())
    assert receipt["findingsAreSynthetic"] and receipt["observations"] == 2
    (evidence / "source-before.sha256").write_text(hashlib.sha256((root / "main.rs").read_bytes()).hexdigest())
    native(root, evidence, "native-export", "report:sarif", {"output":"native-confirmed.sarif"})
    error = native(root, evidence, "outside-refusal", "report:sarif", {"output":"../must-not-write.sarif"}, False)
    assert "output path may not contain .." in error and not (root.parent / "must-not-write.sarif").exists()
    (evidence / "shell-command.txt").write_text('run report:sarif {"output":"shell-confirmed.sarif"}')
    check_document(root / "native-confirmed.sarif")


def check_document(path):
    document = json.loads(path.read_text())
    run = document["runs"][0]
    assert run["properties"]["kuzushiExport"]["scope"] == "workspace_history"
    assert len(run["results"]) == 1
    properties = run["results"][0]["properties"]
    assert properties["kuzushiReviewDecision"] == "confirmed"
    assert properties["kuzushiReviewDecisionAuthor"] == "human"
    assert properties["kuzushiReviewDecisionBasis"]["runId"] == "owned-alpha"
    assert properties["kuzushiReviewDecisionBasis"]["laterObservation"]["runId"] == "owned-beta"
    assert properties["kuzushiSourceApplicability"] == "reassessment_required"
    assert properties["kuzushiSourceApplicabilityBasis"] == "recorded_observations"
    assert properties["kuzushiCurrentCheckoutApplicability"] == "not_assessed"


def verify(root, evidence, stage):
    assert hashlib.sha256((root / "main.rs").read_bytes()).hexdigest() == (evidence / "source-before.sha256").read_text()
    check_document(root / "native-confirmed.sarif")
    check_document(root / "shell-confirmed.sarif")
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 2
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 1
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts"]:
            if table in tables: assert db.execute("select count(*) from " + table).fetchone()[0] == 0
    (evidence / (stage + "-check.json")).write_text(json.dumps({"sourceUnchanged":True,"observations":2,"humanDecisions":1,"exportResults":1,"providerRequests":0,"scannerJobs":0}, indent=2) + "\n")


root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
if stage == "seed": seed(root, evidence)
else: verify(root, evidence, stage)
