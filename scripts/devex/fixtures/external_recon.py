"""Owned external-observation stubs. No service, scanner or provider is contacted."""
import hashlib
import json
import os
import shlex
import sqlite3
import sys
import time
from pathlib import Path
from advisory_observations import decision_digest
from reviewed_lessons import prepare
from rejected_context import execute

TOOLS = {"nmap": "recon:nmap", "passive": "recon:subdomain", "http": "recon:http-fingerprint"}


def script(evidence, name, body):
    path = evidence / (name + "-stub")
    marker = shlex.quote(str(evidence / "stub-invocations.txt"))
    path.write_text("#!/bin/sh\nprintf '%s\\n' " + shlex.quote(name) + " >> " + marker + "\n" + body + "\n")
    path.chmod(0o700)
    return str(path)


def seed(root, evidence):
    prepare(root, evidence)
    (evidence / "decision-before.sha256").write_text(decision_digest(root))
    stub = {
        "nmap": script(evidence, "nmap", "printf 'Host: 192.0.2.10 (owned.invalid) Ports: 80/open/tcp//http///\\n'"),
        "passive": script(evidence, "passive", "printf '[{\"name_value\":\"api.owned.invalid\"}]'"),
        "http": script(evidence, "http", "printf 'HTTP/1.1 200 OK\\r\\nServer: OwnedFixture\\r\\n\\r\\n<html><title>Labeled synthetic greeting</title></html>'"),
        "deadline": script(evidence, "deadline", "exec sleep 5"),
    }
    commands = {
        "nmap": (TOOLS["nmap"], {"target": "192.0.2.10", "ports": "80", "binary": stub["nmap"]}),
        "passive": (TOOLS["passive"], {"domain": "owned.invalid", "source": "crtsh", "binary": stub["passive"]}),
        "http": (TOOLS["http"], {"target": "http://owned.invalid/", "binary": stub["http"]}),
        "missing": (TOOLS["nmap"], {"target": "192.0.2.10", "binary": str(evidence / "absent-program")}),
        "deadline": (TOOLS["nmap"], {"target": "192.0.2.10", "binary": stub["deadline"], "timeoutSeconds": 1}),
    }
    for name, (tool, value) in commands.items():
        (evidence / (name + ".txt")).write_text("run " + tool + " " + json.dumps(value))


def result_for(root, tool):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        rows = [(p.parent, json.loads(p.read_text())) for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
        rows = [(p, row) for p, row in rows if row.get("tool") == tool and row.get("status") == "partial"]
        if len(rows) == 1:
            path, run = rows[0]
            assert not run.get("phase")
            return path, run, json.loads((path / "result.json").read_text())
        time.sleep(.05)
    raise AssertionError(rows)


def verify(root, evidence, stage):
    assert decision_digest(root) == (evidence / "decision-before.sha256").read_text()
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest() == (evidence / "source-before.sha256").read_text()
    active = json.loads((evidence / "active-before.json").read_text())
    assert hashlib.sha256(Path(active["path"]).read_bytes()).hexdigest() == active["sha256"]
    names = ["nmap", "passive", "http"][:{"nmap": 1, "passive": 2}.get(stage, 3)]
    db_path = None
    for name in names:
        path, run, result = result_for(root, TOOLS[name])
        data = result["data"]
        assert result["status"] == "partial" and data["sourceVerified"] is False and data["coverage"]["complete"] is False
        if name == "passive":
            assert data["hosts"][0]["state"] == "unknown"
        db_path = Path(data["persisted"]["db"])
        digest = hashlib.sha256((path / "result.json").read_bytes()).hexdigest()
        saved = evidence / (name + "-result.sha256")
        if saved.exists():
            assert digest == saved.read_text()
        else:
            saved.write_text(digest)
        (evidence / (name + "-replay.txt")).write_text("replay " + run["runId"])
    with sqlite3.connect(db_path.as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        if "passive" in names:
            state, metadata = db.execute("select state, metadata_json from hosts where address='api.owned.invalid'").fetchone()
            assert state == "unknown" and json.loads(metadata)["livenessTested"] is False
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 1
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 1
    if stage in ["failure", "restart"]:
        assert (evidence / "stub-invocations.txt").read_text().splitlines() == ["nmap", "passive", "http", "deadline"]
        failures = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/runs").glob("*/result.json")]
        assert any(row.get("status") == "failed" and "process deadline reached" in json.dumps(row) for row in failures)
    lessons = execute(root, Path(os.environ["HOME"]), evidence, "lessons-" + stage, "findings:lessons", {})
    assert lessons["rows"] == []
    (evidence / (stage + "-check.json")).write_text(json.dumps({"partialRuns": len(names), "providerCalls": 0,
        "networkRequests": 0, "sourceExecution": False, "capturesAreSynthetic": True,
        "exactHumanDecisionPreserved": True, "activeContextUnchanged": True, "acceptedLessons": 0,
        "phaseContinuation": False}, indent=2) + "\n")


if __name__ == "__main__":
    stage, root, evidence = sys.argv[1:]
    root, evidence = Path(root).resolve(), Path(evidence).resolve()
    if stage == "seed":
        seed(root, evidence)
    else:
        verify(root, evidence, stage)
