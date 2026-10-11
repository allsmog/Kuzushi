"""Owned synthetic credential shapes, read-only inspection and real ledger consumers."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def native(root, evidence, name, tool, value):
    env = dict(os.environ, HOME=str(evidence / "home"))
    for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KUZUSHI_MODEL", "NODE_OPTIONS"]:
        env.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"],"--plain","--target",str(root),"run",tool,"--input",json.dumps(value)],
        env=env,capture_output=True,text=True,timeout=35)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, (name,result.stderr)
    value = json.loads(result.stdout)
    save(evidence,name,value)
    return value


def source_hashes(root):
    return {name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ["a.env","b.env"]}


def seed(root, evidence, home):
    for name in ["app.py","config.env"]: (root/name).unlink(missing_ok=True)
    for name in ["a.env","b.env"]:
        text = "# Owned synthetic fixture. No active credential or defect claimed.\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        (root/name).write_text(text + "#" + "x"*700 + "\n")
    (evidence / "finding-command.txt").write_text('run secret-scan:scan {"maxFindings":1}')
    (evidence / "bytes-command.txt").write_text('run secret-scan:scan {"maxTotalBytes":1024}')
    (evidence / "entries-command.txt").write_text('run secret-scan:scan {"maxEntries":2}')
    save(evidence,"before",{"sources":source_hashes(root)})


def results(root):
    return [json.loads(p.read_text()) for p in sorted((root/".kuzushi/v3/runs").glob("*/result.json"))]


def ledger_reader(root, evidence):
    path = root / ".kuzushi/v3/index.sqlite3"
    wal = path.with_name(path.name + "-wal")
    if wal.exists() and wal.stat().st_size:
        return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    # An absent WAL means committed pages are in the main file. Copy only a
    # stable checkpointed image so read-only inspection never creates sidecars.
    data = path.read_bytes()
    assert not wal.exists() or wal.stat().st_size == 0, "Writer started during snapshot"
    assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(data).digest()
    snapshot = evidence / "checkpointed-ledger.sqlite3"
    snapshot.write_bytes(data)
    return sqlite3.connect(snapshot.as_uri() + "?mode=ro&immutable=1", uri=True)


def verify(root, evidence, stage):
    assert source_hashes(root) == json.loads((evidence/"before.json").read_text())["sources"]
    reports = [r for r in results(root) if isinstance(r.get("data"),dict) and "inspection" in r["data"]]
    assert reports and all(r["status"] == "partial" for r in reports)
    for report in reports:
        info = report["data"]["inspection"]
        assert info["traversalEntries"] <= info["maxEntries"]
        assert info["contentBytesReserved"] <= info["maxTotalBytes"]
        assert report["data"]["coverageGaps"]["gaps"]
        assert all(f["staticProofState"] == "signal_only" for f in report["data"].get("coreFindings",[]))
    with ledger_reader(root,evidence) as db:
        tables={r[0] for r in db.execute("select name from sqlite_master where type='table'")}
        counts={name:db.execute("select count(*) from "+name).fetchone()[0] if name in tables else 0
            for name in ["finding_observations","review_decisions","investigation_call_reservations","investigation_work_attempts"]}
    assert counts["investigation_call_reservations"] == 0 and counts["investigation_work_attempts"] == 0
    if stage in ["all-limits","exported","restarted"]:
        assert len(reports) >= 3
        assert any(r["data"]["inspection"]["maxEntries"]==2 for r in reports)
        assert any(r["data"]["inspection"]["maxTotalBytes"]==1024 for r in reports)
    if stage in ["exported","restarted"]:
        native(root,evidence,stage+"-ledger","findings:list",{})
        paths=list((root/".kuzushi/reports").glob("*.json"))
        assert paths and any('false_positive' in p.read_text() and 'signal_only' in p.read_text() for p in paths)
        assert counts["review_decisions"] == 1
    assert not list((root/".kuzushi/v3/campaigns").glob("*/queue.json"))
    save(evidence,stage+"-verified",{"sourcesUnchanged":True,"limitsRespected":True,"counts":counts,"providerRequests":0,"scannerReports":len(reports)})


root,evidence = [Path(p).resolve() for p in sys.argv[1:3]]
if sys.argv[3]=="seed": seed(root,evidence,Path(sys.argv[4]).resolve())
else: verify(root,evidence,sys.argv[3])
