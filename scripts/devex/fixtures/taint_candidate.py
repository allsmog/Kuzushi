"""Owned missing-model checks. No analysis engine, model, network or source execution."""
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

TOOL = "taint-iris-next:finding-review"


def prepare(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    source = root / "README.md"
    source.write_text("Owned directory metadata. No source program or context.\n")
    (evidence / "source.sha256").write_text(hashlib.sha256(source.read_bytes()).hexdigest())
    (evidence / "command.txt").write_text("run " + TOOL + ' {"backend":"structural","discoverSignals":false}')
    bridge = Path(__file__).resolve().parents[2] / "langgraph-bridge.mjs"
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True,exist_ok=True)
    config.write_text("[runtime]\nlanggraph_bridge_command = " + json.dumps(["node",str(bridge)]) + "\n")


def verify(root, evidence, stage):
    count = 0 if stage=="before" else 1
    deadline = time.monotonic()+15
    while time.monotonic()<deadline:
        runs = [(p.parent,json.loads(p.read_text())) for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
        if len(runs)==count and all(r["status"]!="running" for _,r in runs):break
        time.sleep(0.05)
    assert len(runs)==count
    assert hashlib.sha256((root / "README.md").read_bytes()).hexdigest()==(evidence / "source.sha256").read_text()
    for path,run in runs:
        assert run["tool"]==TOOL and run["status"]=="blocked"
        assert not run.get("model") and not run.get("phase")
        result = json.loads((path / "result.json").read_text())
        assert result["status"]=="blocked"
        assert "model" in result["summary"].lower()
        digest = hashlib.sha256((path / "result.json").read_bytes()).hexdigest()
        if stage=="failed":
            (evidence / "result.sha256").write_text(digest)
            (evidence / "replay.txt").write_text("replay "+run["runId"])
        else:assert digest==(evidence / "result.sha256").read_text()
    counts = inspect_no_analysis(root)
    (evidence / (stage+"-check.json")).write_text(json.dumps({"toolRuns":count,
        "providerRequests":0,"sourceExecution":False,"sourceUnchanged":True,"accountingTables":counts},indent=2)+"\n")


def inspect_no_analysis(root):
    names = ["finding_observations","review_decisions","investigation_call_reservations","investigation_work_attempts"]
    counts = dict.fromkeys(names)
    dbpath = root / ".kuzushi/v3/index.sqlite3"
    if dbpath.exists():
        with sqlite3.connect(dbpath.as_uri()+"?mode=rw",uri=True) as db:
            db.execute("PRAGMA query_only=ON")
            tables = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
            for name in names:
                n = db.execute("select count(*) from "+name).fetchone()[0] if name in tables else None
                assert n in [None,0]
                counts[name] = n
    for path in (root / ".kuzushi/v3/runs").glob("*/items.jsonl"):
        for line in path.read_text().splitlines():
            assert not json.loads(line)["item"]["type"].startswith("model_call")
    return counts


if __name__=="__main__":
    root,evidence,stage = Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
    if stage=="prepare":prepare(root,evidence,Path(sys.argv[4]).resolve())
    else:verify(root,evidence,stage)
