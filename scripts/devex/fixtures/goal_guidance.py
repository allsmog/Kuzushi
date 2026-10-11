"""Owned goal-guided context planning. No generator or provider request runs."""
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
    for key in ["OPENAI_API_KEY","ANTHROPIC_API_KEY","KUZUSHI_MODEL","KUZUSHI_LANGGRAPH_BRIDGE","NODE_OPTIONS"]:
        env.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"],"--plain","--target",str(root),"run",tool,"--input",json.dumps(value)],env=env,capture_output=True,text=True,timeout=35)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, (name,result.stderr)
    response = json.loads(result.stdout)
    save(evidence,name,response)
    return response["data"]


def seed(root, evidence, home):
    for name in ["app.py","config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "main.rs").write_text("// Owned greeting. Never compiled or executed.\nfn main() { println!(\"hello\"); }\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True,exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    text = "Original goal\nExplain how the owned greeting reaches the terminal.\n\nPriorities\nKeep source facts and operator intent separate.\n\nOwner questions\n東京 notes stay exact. Who owns this component?\n"
    brief = native(root,evidence,"first-brief","campaign:brief",{"mode":"save","expectedRevision":0,"text":text})["brief"]
    save(evidence,"before",{"sourceSha256":hashlib.sha256((root/"main.rs").read_bytes()).hexdigest(),"brief":brief})


def planned(root, evidence):
    paths = list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    assert len(paths) == 1
    path = paths[0]
    document = json.loads(path.read_text())
    before = json.loads((evidence/"before.json").read_text())
    assert len(document["jobs"]) == 1 and document["workers"] == 1
    assert document["jobs"][0]["input"]["operatorBriefRef"] == before["brief"]["reference"]
    assert document["investigationBrief"] == before["brief"]
    assert document["jobs"][0]["input"]["activate"] is False
    save(evidence,"frozen-plan",{"path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"campaignId":document["campaignId"]})
    native(root,evidence,"second-brief","campaign:brief",{"mode":"save","expectedRevision":1,"text":"Later replacement goal"})
    (evidence/"exact-command.txt").write_text("run campaign:brief " + json.dumps({"briefRef":before["brief"]["reference"]}))
    verify(root,evidence)


def verify(root, evidence):
    before = json.loads((evidence/"before.json").read_text())
    frozen = json.loads((evidence/"frozen-plan.json").read_text())
    assert hashlib.sha256(Path(frozen["path"]).read_bytes()).hexdigest() == frozen["sha256"]
    assert hashlib.sha256((root/"main.rs").read_bytes()).hexdigest() == before["sourceSha256"]
    assert not list((root/".kuzushi/v3/campaigns").glob("*/queue.json"))
    assert not (root/".kuzushi/threat-models/manifest.json").exists()
    counts={}
    path=root/".kuzushi/v3/index.sqlite3"
    if path.exists():
        with sqlite3.connect(path.as_uri()+"?mode=ro",uri=True) as db:
            tables={row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            for name in ["finding_observations","review_decisions","investigation_work_attempts","investigation_call_reservations"]:
                counts[name]=db.execute("select count(*) from "+name).fetchone()[0] if name in tables else 0
    assert all(value==0 for value in counts.values())
    save(evidence,"verified",{"counts":counts,"sourceUnchanged":True,"jobsStarted":0,"providerRequests":0,"goalRevision":1,"currentHeadRevision":2})


root,evidence=[Path(value).resolve() for value in sys.argv[1:3]]
if sys.argv[3]=="seed": seed(root,evidence,Path(sys.argv[4]).resolve())
elif sys.argv[3]=="planned": planned(root,evidence)
else: verify(root,evidence)
