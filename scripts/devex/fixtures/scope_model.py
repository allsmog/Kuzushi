"""One real scope executor with intercepted transport. No live model or scans."""
import json
import hashlib
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
import exact_scope
import inventory_input

SOURCES = ["[route].py", "root file.py", "excluded.py", "reader.py"]


def seed(root, evidence, home):
    exact_scope.seed(root, evidence)
    path = evidence / "alpha-context.json"
    alpha = json.loads(path.read_text())
    alpha["systemContext"] = 'Selected Alpha architecture: a human reviews the owned "root file.py" and [route].py source.\nLoose parent files remain explicit discovery work; no runtime or vulnerability claim is made.'
    path.write_text(json.dumps(alpha, indent=2) + "\n")
    (evidence / "selected-overview.json").write_text(json.dumps(alpha["systemContext"]) + "\n")
    (evidence / "source-before.json").write_text(json.dumps({name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in SOURCES}) + "\n")
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/scope_provider.mjs", evidence / "provider.mjs")
    credentials = home / ".kuzushi/oauth-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex": {"access": "offline-scope-fixture", "expires": 99999999999999}}))
    credentials.chmod(0o600)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    command = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n'
                      + 'langgraph_bridge_command = ' + json.dumps(command) + '\n'
                      + '[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\nallow_env_token = false\n')
    (evidence / "priorities.txt").write_text("Preserve coherent services\nKeep loose parent files")


def plans(root):
    return [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]


def verify(root, evidence, stage):
    assert {name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in SOURCES} == json.loads((evidence / "source-before.json").read_text())
    documents = plans(root)
    scope_plans = [plan for plan in documents if plan.get("tool") == "pack:suggest-scopes"]
    assert len(scope_plans) == 1
    plan = scope_plans[0]
    assert len(plan["jobs"]) == 1 and plan["workers"] == 1
    assert plan["jobs"][0]["input"].get("allowanceRef") is None
    assert plan["model"] == "openai-codex:gpt-5.5"
    assert "loose parent files" in plan["jobs"][0]["input"]["priorities"]
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    calls_path = evidence / "provider-calls.jsonl"
    if stage == "finished":
        for _ in range(45):
            queue = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
            if queue.exists() and all(job["state"] == "completed" for job in json.loads(queue.read_text())["jobs"].values()):
                break
            time.sleep(1)
    calls = [json.loads(line) for line in calls_path.read_text().splitlines()] if calls_path.exists() else []
    expected = 0 if stage == "draft" else 1
    assert len(calls) == expected
    if calls:
        overview = json.loads((evidence / "selected-overview.json").read_text())
        assert calls[0]["architectureContext"]["omitted"] == 0
        assert {"field":"/systemContext", "value":overview} in calls[0]["architectureContext"]["items"]
    beta = json.loads((evidence / "active-beta-ref.json").read_text())
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == beta
    db = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for table in ("investigation_call_reservations", "investigation_work_attempts"):
            if table in tables:
                assert connection.execute(f"select count(*) from {table}").fetchone()[0] == expected
    if stage == "scan-draft":
        scans = [plan for plan in documents if plan.get("kind") == "scan-batch"]
        assert len(scans) == 1 and scans[0]["investigationId"] == plan["investigationId"]
        assert len(scans[0]["jobs"]) == 3 and scans[0]["workers"] == 1
        assert not (root / ".kuzushi/v3/campaigns" / scans[0]["campaignId"] / "queue.json").exists()
    (evidence / ("scope-model-" + stage + ".json")).write_text(json.dumps({
        "stage": stage, "proposalJobs": 1, "interceptedProviderRequests": expected,
        "liveProviderRequests": 0, "discoveryJobsStarted": 0,
        "investigationId": plan["investigationId"], "scopeGroupingIsSynthetic": True,
    }, indent=2) + "\n")


def show_architecture_input(root, evidence):
    pane = inventory_input.owned_pane(root.resolve())
    subprocess.run(["tmux", "send-keys", "-t", pane, "Home", "Down", "Home"], check=True)
    time.sleep(0.15)
    for page in range(100):
        text = subprocess.check_output(["tmux", "capture-pane", "-p", "-t", pane], text=True)
        if "Context sections: 5/5; omitted 0." in text:
            size = subprocess.check_output(["tmux", "display-message", "-p", "-t", pane,
                "#{pane_width}x#{pane_height}"], text=True).strip()
            assert size != "40x12" or page <= 6, "The compact input receipt must precede long provenance"
            (evidence / ("architecture-input-" + size + ".json")).write_text(json.dumps({
                "viewport":size,"pageDownPresses":page,"sectionsSupplied":5,
                "sectionsOmitted":0,"liveProviderRequests":0},indent=2) + "\n")
            verify(root, evidence, "input-view")
            return
        subprocess.run(["tmux", "send-keys", "-t", pane, "NPage"], check=True)
        time.sleep(0.12)
    raise AssertionError("The architecture input receipt was not reachable within 100 pages")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "input-view":
        show_architecture_input(root, evidence)
    else:
        verify(root, evidence, stage)
