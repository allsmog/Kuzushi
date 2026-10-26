"""Canonical report counters over owned, inert repeated observations."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from secret_settings import ledger


def native(root, evidence, label, tool, value):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root), "run", tool, "--input", json.dumps(value)], capture_output=True, text=True, timeout=40)
    (evidence / (label + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    (evidence / (label + ".json")).write_text(json.dumps(document, indent=2) + "\n")
    return document


def raw_observation_hash(root, evidence):
    with ledger(root, evidence) as db:
        rows = db.execute("select rowid, * from finding_observations order by rowid").fetchall()
    return hashlib.sha256(repr(rows).encode()).hexdigest()


def seed(root, evidence):
    subprocess.run([sys.executable, "-B", str(Path(__file__).with_name("confirmed_sarif.py")), str(root), str(evidence), "seed"], check=True, timeout=50)
    fixture = json.loads((root / ".kuzushi/sarif-fixture.json").read_text())
    command = "run findings:dismiss " + json.dumps({"fingerprint": fixture["fingerprint"], "reason": "false_positive", "note": "Owned fixture routing decision. No security claim.", "author": "operator"})
    (evidence / "dismiss-command.txt").write_text(command)
    value = native(root, evidence, "before-status", "campaign:status", {})
    assert value["data"]["trend"]["confirmedFindings"] == 1
    assert value["data"]["trend"]["decidedFindings"] == 1
    (evidence / "raw-observations-before.sha256").write_text(raw_observation_hash(root, evidence))


def verify(root, evidence, stage):
    status = native(root, evidence, stage + "-status", "campaign:status", {})
    exported = native(root, evidence, stage + "-export", "report:sarif", {"output": stage + "-after-fp.sarif"})
    report = json.loads(Path(exported["data"]["path"]).read_text())
    trend = report["runs"][0]["properties"]["kuzushiTrend"]
    assert report["runs"][0]["results"] == []
    assert trend["confirmedFindings"] == 0 and trend["decidedFindings"] == 1
    assert trend["rejectedFalsePositives"] == 1 and trend["fpRate"] == 1.0
    assert trend["costPerConfirmedUsd"] is None
    assert trend == status["data"]["trend"]
    ci = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root), "ci"], capture_output=True, text=True, timeout=40)
    (evidence / (stage + "-ci.stdout.txt")).write_text(ci.stdout)
    (evidence / (stage + "-ci.stderr.txt")).write_text(ci.stderr)
    assert ci.returncode == 0, ci.stderr
    summary = json.loads((root / ".kuzushi/v3/reports/ci-summary.json").read_text())
    assert summary["confirmedCount"] == 0 and summary["trend"] == trend
    with ledger(root, evidence) as db:
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 2
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 2
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts"]:
            if table in tables:
                assert db.execute("select count(*) from " + table).fetchone()[0] == 0
    assert raw_observation_hash(root, evidence) == (evidence / "raw-observations-before.sha256").read_text()
    assert hashlib.sha256((root / "main.rs").read_bytes()).hexdigest() == (evidence / "source-before.sha256").read_text()
    result = {"confirmed": 0, "decided": 1, "rejectedFalsePositives": 1, "rawObservations": 2, "humanDecisions": 2, "rawObservationsUnchanged": True, "providerRequests": 0, "scannerJobs": 0, "sourceUnchanged": True, "sourceExecuted": False}
    (evidence / (stage + "-check.json")).write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    target, artifacts, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    seed(target, artifacts) if action == "seed" else verify(target, artifacts, action)
