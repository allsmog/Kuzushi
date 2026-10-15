"""Owned historical trace receipts. No provider calls or target execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from reviewed_lessons import prepare


def seed(root, evidence):
    prepare(root, evidence)
    env = dict(os.environ, KUZUSHI_TRACE_FIXTURE_OUT=str(root))
    result = subprocess.run([os.environ["KUZUSHI_TRACE_TEST_BIN"], "--exact",
        "app::tool_runner::run_tool::snapshots::trace_expansion::tests::source_history::prepare_native_trace_history_fixture",
        "--nocapture"], env=env, text=True, capture_output=True, timeout=30)
    (evidence / "trace-preparation.log").write_text(result.stdout + result.stderr)
    result.check_returncode()
    receipt = json.loads((root / ".kuzushi/trace-fixture.json").read_text())
    assert receipt["findingsAreSynthetic"] and receipt["providerRequests"] == 0
    assert receipt["sourceExecuted"] is False
    (evidence / "open-trace-finding.txt").write_text("open " + receipt["fingerprint"])
    (evidence / "earlier-replay.txt").write_text("replay " + receipt["earlierRun"])
    (evidence / "source-before.sha256").write_text(hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest())
    paths = list((root / ".kuzushi/v3/runs").glob("tool-*-trace-*/result.json"))
    assert len(paths) == 2
    (evidence / "trace-result-hashes.json").write_text(json.dumps({str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}))
    verify(root, evidence, "seed")


def verify(root, evidence, stage):
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest() == (evidence / "source-before.sha256").read_text()
    active = json.loads((evidence / "active-before.json").read_text())
    assert hashlib.sha256(Path(active["path"]).read_bytes()).hexdigest() == active["sha256"]
    for path, digest in json.loads((evidence / "trace-result-hashes.json").read_text()).items():
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 1
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 1
    (evidence / (stage + "-check.json")).write_text(json.dumps({"liveRequests": 0,
        "sourceExecution": False, "findingsAreSynthetic": True, "observations": 1,
        "humanDecisions": 1, "traceReceipts": 2, "sourceUnchanged": True,
        "activeContextUnchanged": True, "historicalReceiptsUnchanged": True}, indent=2) + "\n")


if __name__ == "__main__":
    stage, root, evidence = sys.argv[1:]
    root, evidence = Path(root).resolve(), Path(evidence).resolve()
    if stage == "seed":
        seed(root, evidence)
    else:
        verify(root, evidence, stage)
