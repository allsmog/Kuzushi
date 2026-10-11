"""Exact context source checks on an owned fixture. No model or source execution."""
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from context_comparison import git, run_tool
from context_diagram import document
from context_edit import object_path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(root):
    return json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())


def seed(root, evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    (root / "reader.py").write_text('# Labeled fixture, never executed.\nprint("fixture")\n')
    git(root, "init", "--quiet", "--initial-branch=main")
    git(root, "add", "reader.py")
    git(root, "commit", "--quiet", "-m", "Fixture source")
    binary = os.environ["KUZUSHI_NATIVE_BIN"]
    refs = {}
    for key, label in [("original", "Alpha"), ("active", "Beta")]:
        run_tool(binary, root, evidence, "import-" + key, "threat-model:import",
                 {"document": document(label), "label": label, "activate": True})
        refs[key] = manifest(root)["active"]
    revised = run_tool(binary, root, evidence, "revise", "threat-model:revise", {
        "threatModelRef": refs["original"], "label": "Alpha edited",
        "edits": [{"pointer": "/systemContext", "text": "Operator-owned fixture overview."}],
    })
    refs["edited"] = revised["data"]["modelRef"]
    before = {"refs": refs, "manifest": manifest(root), "sha": git(root, "rev-parse", "HEAD"),
              "sourceSha256": digest(root / "reader.py"),
              "mirrorSha256": digest(root / ".kuzushi/threat-model.json"),
              "objects": {key: digest(object_path(root, ref)) for key, ref in refs.items()}}
    (evidence / "before.json").write_text(json.dumps(before, indent=2) + "\n")


def check_saved(root, evidence):
    before = json.loads((evidence / "before.json").read_text())
    current = manifest(root)
    assert current["active"] == before["refs"]["active"]
    assert current["models"][:2] == before["manifest"]["models"][:2]
    assert digest(root / ".kuzushi/threat-model.json") == before["mirrorSha256"]
    for key, ref in before["refs"].items():
        assert digest(object_path(root, ref)) == before["objects"][key]
    model = current["models"][2]
    assert len(current["models"]) == 3 and len(model["revisions"]) == 2
    revision = model["revisions"][-1]
    reference = {"modelId": model["modelId"], "revisionId": revision["revisionId"], "sha256": revision["sha256"]}
    assert revision["source"] == "verify" and revision["sourceRevisionId"] == before["refs"]["edited"]["revisionId"]
    assert revision["scope"] == model["revisions"][0]["scope"]
    checked = json.loads(object_path(root, reference).read_text())
    original = json.loads(object_path(root, before["refs"]["edited"]).read_text())
    assert checked["provenance"] == original["provenance"]
    assert "verification" in checked and "verification" not in original
    assert digest(root / "reader.py") == before["sourceSha256"]
    assert git(root, "rev-parse", "HEAD") == before["sha"]
    receipt = {"checkedRef": reference, "verdict": checked["verification"]["verdict"],
               "activeUnchanged": True, "originalObjectsUnchanged": True, "sourceUnchanged": True,
               "sourceSha": before["sha"], "manifestSha256": digest(root / ".kuzushi/threat-models/manifest.json")}
    (evidence / "saved-check.json").write_text(json.dumps(receipt, indent=2) + "\n")


def change_source(root, evidence, kind):
    if kind == "dirty":
        (root / "reader.py").write_text('# Changed fixture content, never executed.\nprint("changed")\n')
    else:
        original = git(root, "show", "HEAD:reader.py") + "\n"
        (root / "reader.py").write_text(original)
        git(root, "commit", "--quiet", "--allow-empty", "-m", "Fixture revision")
    before = json.loads((evidence / "before.json").read_text())
    sha = git(root, "rev-parse", "HEAD")
    assert (sha == before["sha"]) == (kind == "dirty")
    assert (digest(root / "reader.py") == before["sourceSha256"]) == (kind == "sha")
    (evidence / (kind + "-source.json")).write_text(json.dumps({"sha": sha, "sourceSha256": digest(root / "reader.py")}, indent=2) + "\n")


def check_stopped(root, evidence, kind):
    saved = json.loads((evidence / "saved-check.json").read_text())
    assert digest(root / ".kuzushi/threat-models/manifest.json") == saved["manifestSha256"]
    (evidence / (kind + "-stopped.json")).write_text(json.dumps({"noRevisionPublished": True,
        "activeUnchanged": True, "historicalContextPreserved": True, "jobsStarted": 0, "providerRequests": 0}) + "\n")


def check_plan(root, evidence):
    saved = json.loads((evidence / "saved-check.json").read_text())
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    assert len(plans) == 1
    plan = plans[0]
    assert plan["baseInput"]["threatModelRef"] == saved["checkedRef"] and plan["trialsPlanned"] == 3
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/jobs/*/result.json"))
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_work_attempts", "investigation_call_reservations"]:
            if table in tables:
                assert db.execute("select count(*) from " + table).fetchone()[0] == 0
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    (evidence / "plan-check.json").write_text(json.dumps({"checkedRef": saved["checkedRef"],
        "plannedJobs": 3, "jobsStarted": 0, "providerRequests": 0, "sourceExecuted": False}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "seed": seed(root, evidence)
    elif action == "saved": check_saved(root, evidence)
    elif action in ["dirty", "sha"]: change_source(root, evidence, action)
    elif action.endswith("-stopped"): check_stopped(root, evidence, action.removesuffix("-stopped"))
    else: check_plan(root, evidence)
