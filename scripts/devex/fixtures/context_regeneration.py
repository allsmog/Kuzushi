"""Real context executor, isolated intercepted transport, no live spending or source execution."""
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from context_comparison import run_tool
from context_diagram import document
from context_edit import object_path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seed(root, evidence, home):
    evidence.mkdir(parents=True, exist_ok=True)
    (root / "reader.py").write_text('# Labeled fixture source, never executed.\nprint("fixture")\n')
    refs = {}
    for key, label in [("selected", "Alpha"), ("active", "Beta")]:
        model = document(label)
        model.update(systemContext="Operator accepted overview α", userEdited=True,
                     openQuestions=[{"question":"Who owns input?", "answer":"Human owner answer"}])
        run_tool(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, "import-" + key,
                 "threat-model:import", {"document":model, "label":label, "activate":True})
        refs[key] = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())["active"]
    before = {"references":refs, "manifest":json.loads((root / ".kuzushi/threat-models/manifest.json").read_text()),
              "source":digest(root / "reader.py"), "mirror":digest(root / ".kuzushi/threat-model.json"),
              "objects":{key:digest(object_path(root, ref)) for key, ref in refs.items()}}
    (evidence / "before.json").write_text(json.dumps(before, indent=2) + "\n")
    (evidence / "guidance.txt").write_text("Clarify selected purpose\nKeep human context α")
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/regeneration_provider.mjs", evidence / "provider.mjs")
    credentials = home / ".kuzushi/oauth-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex":{"access":"offline-regeneration-fixture", "expires":99999999999999}}))
    credentials.chmod(0o600)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    command = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n'
                     + 'langgraph_bridge_command = ' + json.dumps(command) + '\n'
                     + '[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\nallow_env_token = false\n')


def plans(root):
    return [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]


def unchanged(root, evidence):
    before = json.loads((evidence / "before.json").read_text())
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == before["references"]["active"]
    assert manifest["models"][:2] == before["manifest"]["models"]
    assert digest(root / "reader.py") == before["source"]
    assert digest(root / ".kuzushi/threat-model.json") == before["mirror"]
    for key, ref in before["references"].items():
        assert digest(object_path(root, ref)) == before["objects"][key]
    return before, manifest


def verify(root, evidence, stage):
    before, manifest = unchanged(root, evidence)
    jobs = [plan for plan in plans(root) if plan.get("tool") == "threat-model:regenerate"]
    assert len(jobs) == 1
    plan = jobs[0]
    assert len(plan["jobs"]) == 1 and plan["workers"] == 1
    assert plan["jobs"][0]["input"]["threatModelRef"] == before["references"]["selected"]
    assert plan["jobs"][0]["input"]["fields"] == ["/dfd/nodes/1/purpose"]
    assert plan["jobs"][0]["input"]["guidance"] == (evidence / "guidance.txt").read_text()
    assert "allowanceRef" not in plan["jobs"][0]["input"]
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    if stage == "finished":
        queue = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
        for _ in range(45):
            if queue.exists() and all(job["state"] == "completed" for job in json.loads(queue.read_text())["jobs"].values()):
                break
            time.sleep(1)
        assert queue.exists() and all(job["state"] == "completed" for job in json.loads(queue.read_text())["jobs"].values())
        before, manifest = unchanged(root, evidence)
    calls = evidence / "provider-calls.jsonl"
    expected = 0 if stage == "draft" else 1
    assert len(calls.read_text().splitlines()) == expected if calls.exists() else expected == 0
    candidate = None
    if expected:
        assert len(manifest["models"]) == 3
        model = manifest["models"][2]
        revision = model["revisions"][0]
        candidate = {"modelId":model["modelId"], "revisionId":revision["revisionId"], "sha256":revision["sha256"]}
        parent = json.loads(object_path(root, before["references"]["selected"]).read_text())
        value = json.loads(object_path(root, candidate).read_text())
        assert value["systemContext"] == parent["systemContext"] and value["openQuestions"] == parent["openQuestions"]
        assert value["dfd"]["nodes"][1]["description"] == parent["dfd"]["nodes"][1]["description"]
        assert value["dfd"]["nodes"][1]["purpose"].startswith("Labeled regeneration")
        assert value["userEdited"] and "verification" not in value
        assert value["provenance"]["regeneration"]["sourceModelRef"] == before["references"]["selected"]
        assert value["provenance"]["regeneration"]["accepted"] is False
        assert value["provenance"]["regeneration"]["receipt"]["synthesisRequests"] == 1
        assert revision["sourceRevisionId"] == before["references"]["selected"]["revisionId"]
        assert model["scope"] == before["manifest"]["models"][0]["scope"]
        with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
            assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 1
            assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 1
    if stage == "scan-draft":
        scans = [plan for plan in plans(root) if plan.get("kind") == "scan-batch"]
        assert len(scans) == 1 and len(scans[0]["jobs"]) == 3
        assert scans[0]["baseInput"]["threatModelRef"] == candidate
        assert not (root / ".kuzushi/v3/campaigns" / scans[0]["campaignId"] / "queue.json").exists()
    (evidence / (stage + "-check.json")).write_text(json.dumps({"stage":stage, "candidate":candidate,
        "inactive":True, "originalsAndSourceUnchanged":True, "interceptedProviderRequests":expected,
        "liveProviderRequests":0, "sourceExecution":False, "scanJobsStarted":0}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed": seed(root, evidence, Path(sys.argv[4]).resolve())
    else: verify(root, evidence, stage)
