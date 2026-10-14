"""Owned pack metadata and inert source audit. No provider or scanner work."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path


def seed(root, evidence):
    assert root.name == "fixture-target"
    for name in ("app.py", "config.env", "main.rs"):
        (root/name).unlink(missing_ok=True)
    for name in ("app", "shared"):
        (root/name).mkdir(exist_ok=True)
        (root/name/"source.rs").write_text("// Labeled owned source, never executed\n")
    (root/"README.md").write_text("Owned loose root membership\n")
    pack = evidence/"owned-pack"
    pack.mkdir()
    (pack/"pack.toml").write_text("[pack]\nname='owned-pack'\n[products.example]\ntarget_hint='owned'\nshards='shards.toml'\nthreat_model='model.json'\n")
    (pack/"shards.toml").write_text("[shards.whole]\npaths=['.']\n")
    (pack/"model.json").write_text(json.dumps({"threats":[{"id":"owned","title":"Labeled metadata fixture","severity":"info"}]}))
    for name, value in [("limited", {"packDir":str(pack),"maxWalkEntries":1}),
                        ("complete", {"packDir":str(pack)}),
                        ("oversized", {"packDir":str(pack),"maxBytesPerFile":16,"maxReadBytes":16})]:
        (evidence/(name+"-command.txt")).write_text("run pack:lint "+json.dumps(value))
    (evidence/"source-before.json").write_text(json.dumps(source_hashes(root)))


def source_hashes(root):
    return {str(path.relative_to(root)):hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file() and ".kuzushi" not in path.relative_to(root).parts}


def receipts(root):
    return [json.loads(path.read_text()) for path in sorted((root/".kuzushi/v3/runs").glob("*/result.json"))]


def verify(root, evidence, stage):
    assert source_hashes(root)==json.loads((evidence/"source-before.json").read_text())
    results = receipts(root)
    lints = [row for row in results if row.get("data",{}).get("packDir")]
    if stage=="limited":
        assert any(row["status"]=="partial" and row["data"]["coverage"]["entriesExamined"]==1 for row in lints)
    if stage in ("complete","oversized","restarted"):
        assert any(row["status"]=="completed" and row["data"]["coverage"]["complete"] for row in lints)
    if stage in ("oversized","restarted"):
        assert any(row["status"]=="failed" and row["data"]["coverage"]["reservedReadBytes"]==16 for row in lints)
    if stage=="reader":
        captures = [path.read_text() for path in evidence.glob("*-failed-reader-*40x12.txt")]
        assert any("16/16" in text for text in captures), "Narrow paging must expose the retained allowance"
    db = root/".kuzushi/v3/index.sqlite3"
    if db.exists():
        with sqlite3.connect(db.as_uri()+"?mode=ro",uri=True) as connection:
            tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
            for table in ("investigation_call_reservations","investigation_work_attempts","finding_observations"):
                if table in tables: assert connection.execute("select count(*) from "+table).fetchone()[0]==0
    assert not list((root/".kuzushi/v3/campaigns").glob("*/plan.json"))
    phase = root/".kuzushi/v3/workflow/phase-attempts.jsonl"
    assert not phase.exists() or not phase.read_text().strip(), "Auxiliary tools cannot create phase attempts"
    (evidence/(stage+"-check.json")).write_text(json.dumps({"stage":stage,"lintReceipts":len(lints),"sourceUnchanged":True,"providerCalls":0,"scanJobs":0},indent=2)+"\n")


def consume_draft(root,evidence):
    suggestions = [row["data"] for row in receipts(root) if row.get("data",{}).get("draftPath")]
    assert len(suggestions)==1 and suggestions[0]["inventoryComplete"]
    assert suggestions[0]["shardCount"]==1 and suggestions[0]["shards"][0]["path"]=="."
    path = Path(suggestions[0]["draftPath"])
    assert path.is_relative_to(root/".kuzushi")
    (evidence/"owned-pack/shards.toml").write_bytes(path.read_bytes())
    assert not (root/".kuzushi/shards.toml").exists()
    assert not (root/".kuzushi/v3/scan-scopes/revisions").exists()
    (evidence/"draft-consumer.json").write_text(json.dumps(suggestions[0],indent=2)+"\n")


if __name__ == "__main__":
    root,evidence,stage = Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
    if stage=="seed": seed(root,evidence)
    elif stage=="consume-draft": consume_draft(root,evidence)
    else: verify(root,evidence,stage)
