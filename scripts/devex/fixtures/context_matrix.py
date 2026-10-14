"""Native fixed studies with intercepted transport and exact context receipts."""
import hashlib
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from rejected_context import execute
from context_diagram import document


def source_digest(root):
    return hashlib.sha256((root / "main.rs").read_bytes()).hexdigest()


def calls(evidence):
    path = evidence / "matrix-calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def accounting_visibility(root, evidence, visible):
    """Temporarily hide the owned fixture ledger, preserving every allowance row."""
    with sqlite3.connect(root / ".kuzushi/v3/index.sqlite3") as db:
        if not visible:
            rows = db.execute("select * from investigation_allowance_revisions order by revision").fetchall()
            (evidence / "accounting-before-failure.json").write_text(json.dumps(rows))
            db.execute("alter table investigation_allowance_revisions rename to j109_hidden_allowance_revisions")
        else:
            db.execute("alter table j109_hidden_allowance_revisions rename to investigation_allowance_revisions")
            rows = db.execute("select * from investigation_allowance_revisions order by revision").fetchall()
            assert json.loads(json.dumps(rows)) == json.loads((evidence / "accounting-before-failure.json").read_text())
    assert len(calls(evidence)) == 9


def seed(root, evidence, home):
    repo = Path(__file__).resolve().parents[3]
    (root / "main.rs").write_text('// Owned greeting fixture, never executed.\nfn main() { println!("hello"); }\n')
    shutil.copyfile(repo / "scripts/devex/fixtures/matrix_provider.mjs", evidence / "provider.mjs")
    credentials = home / ".kuzushi/matrix-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex":{"access":"offline-matrix-fixture","expires":99999999999999}}))
    credentials.chmod(0o600)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    bridge = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\nlanggraph_bridge_command = ' + json.dumps(bridge)
                     + '\n[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\nallow_env_token = false\n')
    refs = {}
    for name in ["Alpha", "Beta", "Gamma"]:
        value = document(name)
        value["systemContext"] = name + " labeled experiment context. The source prints a greeting."
        value["attackSurface"]["entryPoints"][0]["path"] = "main.rs"
        value["attackSurface"]["entryPoints"][0]["evidence"] = "main.rs:1"
        result = execute(root, home, evidence, "import-" + name, "threat-model:import", {"document":value,"label":name,"activate":True})
        refs[name] = result["modelRef"]
    before = {"refs":refs,"sourceSha256":source_digest(root),"activeMirrorSha256":hashlib.sha256((root / ".kuzushi/threat-model.json").read_bytes()).hexdigest()}
    (evidence / "before.json").write_text(json.dumps(before,indent=2) + "\n")


def verify(root, evidence, stage):
    before = json.loads((evidence / "before.json").read_text())
    assert source_digest(root) == before["sourceSha256"]
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == before["refs"]["Gamma"]
    assert hashlib.sha256((root / ".kuzushi/threat-model.json").read_bytes()).hexdigest() == before["activeMirrorSha256"]
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    matrices = [plan for plan in plans if plan.get("kind") == "context-matrix"]
    assert len(matrices) == 1
    plan = matrices[0]
    assert len(plan["contextMatrix"]["cases"]) == 3 and plan["jobCount"] == 9 and plan["workers"] == 1
    refs = [case["baseInput"]["threatModelRef"] for case in plan["contextMatrix"]["cases"]]
    assert refs == [before["refs"][name] for name in ["Alpha","Beta","Gamma"]]
    assert plan["contextMatrix"]["baselineCaseId"] == plan["contextMatrix"]["cases"][0]["id"]
    assert all(case["passes"] == 3 for case in plan["contextMatrix"]["cases"])
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    expected = 0 if stage == "draft" else 9
    if stage == "finished":
        queue = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
        for _ in range(45):
            if queue.exists() and all(job["state"] == "completed" for job in json.loads(queue.read_text())["jobs"].values()): break
            time.sleep(1)
        assert queue.exists() and all(job["state"] == "completed" for job in json.loads(queue.read_text())["jobs"].values())
    assert len(calls(evidence)) == expected
    if expected:
        with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro",uri=True) as db:
            assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 9
            assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 9
    (evidence / (stage + "-check.json")).write_text(json.dumps({"interceptedRequests":expected,"liveRequests":0,"sourceExecuted":False,
        "sourceAndActiveContextUnchanged":True,"matrixId":plan["campaignId"],"cases":3,"jobs":9},indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed": seed(root,evidence,Path(sys.argv[4]).resolve())
    elif stage == "hide-accounting": accounting_visibility(root, evidence, False)
    elif stage == "restore-accounting": accounting_visibility(root, evidence, True)
    else: verify(root,evidence,stage)
