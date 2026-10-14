"""Owned immutable-context management and comparison; no model or source execution."""
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from context_comparison import run_tool
from context_diagram import document


def native(root, evidence, label, tool, value):
    return run_tool(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, label, tool, value)


def manifest(root):
    return json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())


def object_path(root, reference):
    digest = reference["sha256"].removeprefix("sha256:")
    assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
    return root / ".kuzushi/threat-models/objects" / ("sha256-" + digest + ".json")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seed(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "reader.py").write_text("# Owned architecture fixture; never executed.\n")
    refs = {}
    for key, label in [("alpha", "Alpha"), ("beta", "Beta")]:
        value = document(label)
        value["systemContext"] = "Owned baseline overview " + label
        value["openQuestions"] = [{"id":"q-owner", "question":"Who owns the input?", "answer":"Baseline owner"}]
        refs[key] = native(root, evidence, "import-" + key, "threat-model:import", {"document":value,"label":label,"activate":True})["data"]["modelRef"]
    refs["copy"] = native(root, evidence, "save-copy", "threat-model:revise", {
        "threatModelRef":refs["alpha"], "label":"Reviewed Alpha",
        "edits":[{"pointer":"/systemContext","text":"Reviewed overview α\nSecond line"},
                 {"pointer":"/dfd/nodes/1/purpose","text":"Keep reviewed context for the operator."},
                 {"pointer":"/openQuestions/0/answer","text":"Application owner"}]
    })["data"]["modelRef"]
    native(root, evidence, "models", "threat-model:models", {})
    native(root, evidence, "revisions", "threat-model:revisions", {"modelId":refs["alpha"]["modelId"]})
    diff = native(root, evidence, "diff", "threat-model:diff", {"from":refs["alpha"]["revisionId"], "to":refs["copy"]["revisionId"]})
    assert len(diff["data"]["contextText"]) == 3 and diff["data"]["documentChanged"]
    assert "no differences" not in diff["summary"]
    before = {"refs":refs,"manifestSha256":sha(root / ".kuzushi/threat-models/manifest.json"),
              "sourceSha256":sha(root / "reader.py"),"objects":{k:sha(object_path(root,v)) for k,v in refs.items()}}
    (evidence / "before.json").write_text(json.dumps(before,indent=2)+"\n")
    commands = {
        "diff": "threats diff " + refs["alpha"]["revisionId"] + " " + refs["copy"]["revisionId"],
        "activate": "threats activate " + refs["alpha"]["modelId"] + "@" + refs["alpha"]["revisionId"],
        "restore": "threats restore " + refs["alpha"]["revisionId"],
        "adopt": "run threat-model:adopt {}",
    }
    for key, command in commands.items(): (evidence / (key + "-command.txt")).write_text(command)


def verify_common(root, evidence):
    before = json.loads((evidence / "before.json").read_text())
    assert sha(root / "reader.py") == before["sourceSha256"]
    for key, ref in before["refs"].items(): assert sha(object_path(root,ref)) == before["objects"][key]
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri()+"?mode=ro",uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["finding_observations","investigation_work_attempts","investigation_call_reservations"]:
            if table in tables: assert db.execute("select count(*) from "+table).fetchone()[0] == 0
    return before, manifest(root)


def verify(root, evidence, stage):
    before, current = verify_common(root,evidence)
    if stage == "compared":
        assert sha(root / ".kuzushi/threat-models/manifest.json") == before["manifestSha256"]
        assert current["active"] == before["refs"]["beta"]
    elif stage == "activated":
        assert current["active"] == before["refs"]["alpha"]
    elif stage == "restored":
        assert current["active"]["modelId"] == before["refs"]["alpha"]["modelId"]
        assert current["active"]["revisionId"] != before["refs"]["alpha"]["revisionId"]
        active_model = next(m for m in current["models"] if m["modelId"] == current["active"]["modelId"])
        assert active_model["revisions"][-1]["source"] == "restore"
        assert active_model["revisions"][-1]["sourceRevisionId"] == before["refs"]["alpha"]["revisionId"]
    else:
        value = json.loads(object_path(root,current["active"]).read_text())
        assert value["systemContext"] == "Operator mirror note α"
        assert value["userEdited"] and "verification" not in value
        active_model = next(m for m in current["models"] if m["modelId"] == current["active"]["modelId"])
        assert active_model["revisions"][-1]["source"] == "adopt"
    exact = native(root,evidence,stage+"-exact-copy","threat-model:read",{"threatModelRef":before["refs"]["copy"]})
    assert exact["data"]["document"]["systemContext"] == "Reviewed overview α\nSecond line"
    assert manifest(root)["active"] == current["active"]
    (evidence / (stage+"-check.json")).write_text(json.dumps({"active":current["active"],"sourceUnchanged":True,"originalObjectsUnchanged":True,"exactCopyIsolated":True,"providerRequests":0,"scannerJobsStarted":0,"sourceExecuted":False},indent=2)+"\n")


def edit_mirror(root):
    path = root / ".kuzushi/threat-model.json"
    value = json.loads(path.read_text()); value["systemContext"] = "Operator mirror note α"
    path.write_text(json.dumps(value,indent=2)+"\n")


root,evidence,stage = Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
if stage == "seed": seed(root,evidence)
elif stage == "edit-mirror": edit_mirror(root)
else: verify(root,evidence,stage)
