"""Manual immutable context copy and consumer proof. No model or source execution."""
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from context_comparison import run_tool
from context_diagram import document


def source_state(root):
    return hashlib.sha256((root / "reader.py").read_bytes()).hexdigest()


def object_path(root, reference):
    digest = reference["sha256"].removeprefix("sha256:")
    assert len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)
    return root / ".kuzushi/threat-models/objects" / ("sha256-" + digest + ".json")


def seed(root, evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    (root / "reader.py").write_text('# Labeled fixture source, never executed.\nprint("fixture")\n')
    references = {}
    for key, label in [("selected", "Alpha"), ("active", "Beta")]:
        model = document(label)
        model["openQuestions"] = ["Who owns the input?"]
        run_tool(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, "import-" + key,
                 "threat-model:import", {"document": model, "label": label, "activate": True})
        references[key] = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())["active"]
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    before = {"references": references, "manifest": manifest, "sourceSha256": source_state(root),
              "mirrorSha256": hashlib.sha256((root / ".kuzushi/threat-model.json").read_bytes()).hexdigest(),
              "objects": {key: hashlib.sha256(object_path(root, ref).read_bytes()).hexdigest() for key, ref in references.items()}}
    (evidence / "before.json").write_text(json.dumps(before, indent=2) + "\n")
    (evidence / "overview.txt").write_text("Operator overview\nUnicode α")
    (evidence / "answer.txt").write_text("Application owner")


def verify_common(root, evidence):
    before = json.loads((evidence / "before.json").read_text())
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert source_state(root) == before["sourceSha256"]
    assert manifest["active"] == before["references"]["active"]
    assert manifest["models"][:2] == before["manifest"]["models"]
    assert hashlib.sha256((root / ".kuzushi/threat-model.json").read_bytes()).hexdigest() == before["mirrorSha256"]
    for key, reference in before["references"].items():
        assert hashlib.sha256(object_path(root, reference).read_bytes()).hexdigest() == before["objects"][key]
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_work_attempts", "investigation_call_reservations"]:
            if table in tables:
                assert db.execute("select count(*) from " + table).fetchone()[0] == 0
    return before, manifest


def verify_draft(root, evidence):
    _, manifest = verify_common(root, evidence)
    assert len(manifest["models"]) == 2
    (evidence / "draft-check.json").write_text(json.dumps({"noRevisionPublished": True, "activeUnchanged": True, "providerRequests": 0, "sourceExecuted": False}) + "\n")


def verify_copy(root, evidence, stage):
    before, manifest = verify_common(root, evidence)
    assert len(manifest["models"]) == 3
    model = manifest["models"][2]
    assert len(model["revisions"]) == 1
    revision = model["revisions"][0]
    reference = {"modelId": model["modelId"], "revisionId": revision["revisionId"], "sha256": revision["sha256"]}
    value = json.loads(object_path(root, reference).read_text())
    assert value["systemContext"] == "Operator overview\nUnicode αretained-context-draft"
    assert value["openQuestions"][0]["answer"] == "Application owner"
    assert value["userEdited"] and "verification" not in value
    assert revision["source"] == "operator-edit" and revision["sourceRevisionId"] == before["references"]["selected"]["revisionId"]
    assert set(value["provenance"]["operatorEdit"]["fields"]) == {"/systemContext", "/openQuestions/0/answer"}
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    assert len(plans) == 1
    plan = plans[0]
    assert plan["baseInput"]["threatModelRef"] == reference
    assert plan["trialsPlanned"] == 3 and plan["baseInput"]["tasks"] == ["secret-scan"]
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    (evidence / (stage + "-check.json")).write_text(json.dumps({"copyRef": reference, "parentRef": before["references"]["selected"],
        "activeUnchanged": True, "originalObjectsUnchanged": True, "sourceUnchanged": True,
        "plannedJobs": 3, "jobsStarted": 0, "providerRequests": 0, "sourceExecuted": False}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "seed": seed(root, evidence)
    elif action == "draft": verify_draft(root, evidence)
    else: verify_copy(root, evidence, action)
