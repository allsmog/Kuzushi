"""Owned greeting history. Real ledger and readers, no provider or source execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from rejected_context import execute


def prepare(root, evidence):
    environment = dict(os.environ, KUZUSHI_GROUP_RUN_FIXTURE_OUT=str(root))
    result = subprocess.run([os.environ["KUZUSHI_GROUP_RUN_TEST_BIN"], "--exact",
        "app::relationships::groups::tests::source_selection::prepare_native_group_run_fixture", "--nocapture"],
        env=environment, text=True, capture_output=True, timeout=30, check=True)
    (evidence / "preparation.log").write_text(result.stdout + result.stderr)
    receipt = json.loads((root / ".kuzushi/group-run-fixture.json").read_text())
    assert receipt["findingsAreSynthetic"] and not receipt["sourceExecuted"]
    assert receipt["providerRequests"] == 0
    (evidence / "hello-before.sha256").write_text(hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest())
    verify(root, evidence)


def verify(root, evidence):
    page = execute(root, Path(os.environ["HOME"]), evidence, "selected-runs", "findings:groups", {"runIds": ["scan-parent"]})
    assert (page["totalFindings"], page["totalGroups"]) == (1, 1)
    assert page["selectedRunIds"] == ["middle-observation", "scan-parent"]
    member = page["groups"][0]["representative"]
    assert member["runId"] == "latest-observation"
    assert member["matchingRunIds"] == ["middle-observation"]
    expected = json.loads((root / ".kuzushi/group-run-fixture.json").read_text())["latestFindingId"]
    assert member["findingId"] == expected
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 3
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 0
        assert db.execute("select count(*) from rekey_edges").fetchone()[0] == 0
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest() == (evidence / "hello-before.sha256").read_text()
    (evidence / "history-check.json").write_text(json.dumps({"observations": 3, "selectedHistoryRun": "middle-observation",
        "displayedRun": "latest-observation", "findingDecisions": 0, "rekeys": 0, "providerRequests": 0,
        "sourceExecuted": False, "sourceUnchanged": True}, indent=2) + "\n")


if __name__ == "__main__":
    action, target, output = sys.argv[1:]
    {"prepare": prepare, "verify": verify}[action](Path(target).resolve(), Path(output).resolve())
