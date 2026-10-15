"""Owned advisory metadata contract. No model, source execution or network."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

TOOL = "findings:chains"


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    source = root / "README.md"
    source.write_text("Labeled owned metadata. No vulnerability or source execution.\n")
    (evidence / "source.sha256").write_text(hashlib.sha256(source.read_bytes()).hexdigest())
    test = Path(os.environ["KUZUSHI_CORE_TEST_BIN"])
    env = dict(os.environ, KUZUSHI_CHAIN_FIXTURE_TARGET=str(root))
    subprocess.run([str(test), "modules::registry::findings_chains_contract_tests::export_owned_chains_ledger_fixture", "--ignored", "--exact"], env=env, check=True)
    with sqlite3.connect(root / ".kuzushi/v3/index.sqlite3") as db:
        assert db.execute("select count(*) from finding_current").fetchone()[0] == 3
        (evidence / "ledger-before.json").write_text(json.dumps(ledger_snapshot(db)))
    (evidence / "run-command.txt").write_text("run " + TOOL + ' {"max_chains":1}')


def verify(root, evidence, stage):
    assert hashlib.sha256((root / "README.md").read_bytes()).hexdigest() == (evidence / "source.sha256").read_text()
    records = []
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        records = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
        matches = [r for r in records if r.get("tool") == TOOL]
        if stage == "before" or len(matches) == 1 and matches[0]["status"] == "completed":
            break
        time.sleep(0.1)
    matches = [r for r in records if r.get("tool") == TOOL]
    assert len(matches) == (0 if stage == "before" else 1)
    with sqlite3.connect(root / ".kuzushi/v3/index.sqlite3") as db:
        db.execute("PRAGMA query_only=ON")
        assert db.execute("select count(*) from finding_current").fetchone()[0] == 3
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 2
        assert ledger_snapshot(db) == json.loads((evidence / "ledger-before.json").read_text())
        tables = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
        accounting = {}
        for table in ["investigation_call_reservations", "investigation_work_attempts"]:
            count = db.execute("select count(*) from " + table).fetchone()[0] if table in tables else None
            assert count in [0, None]
            accounting[table] = count
    for path in (root / ".kuzushi/v3/runs").glob("*/items.jsonl"):
        for line in path.read_text().splitlines():
            assert not json.loads(line)["item"]["type"].startswith("model_call")
    for path in (root / ".kuzushi").glob("**/phase-attempts*.jsonl"):
        assert not path.read_text().strip(), "Advisory fold created phase progress"
    if stage != "before":
        report = json.loads((root / ".kuzushi/v3/reports/chains.json").read_text())
        assert report["confirmedCount"] == 2 and len(report["chains"]) == 1
        (evidence / "replay-command.txt").write_text("replay " + matches[0]["runId"])
    (evidence / (stage + "-check.json")).write_text(json.dumps({"toolRuns":len(matches),"ledgerFindings":3,
        "humanFixtureDecisions":2,"ledgerUnchanged":True,"providerRequests":0,
        "sourceExecuted":False,"sourceUnchanged":True,"accountingTables":accounting}) + "\n")


def ledger_snapshot(db):
    return {table: [list(row) for row in db.execute("select * from " + table + " order by rowid")]
            for table in ["finding_current", "finding_observations", "review_decisions"]}


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "prepare": prepare(root, evidence)
    else: verify(root, evidence, stage)
