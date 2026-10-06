"""Real offline import and study receipts for Map revision isolation, no provider work."""
import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from context_comparison import run_tool
from context_diagram import document


def seed(root, evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    (root / "reader.py").write_text('print("Labeled Map fixture")\n')
    binary = os.environ["KUZUSHI_NATIVE_BIN"]
    run_tool(binary, root, evidence, "map-preparation", "context:build", {})
    beta = run_tool(binary, root, evidence, "active-beta", "threat-model:import",
                    {"document": document("Beta"), "label": "Beta", "activate": True})
    (evidence / "active-beta-ref.json").write_text(json.dumps(beta["data"]["modelRef"]))
    path = evidence / "alpha-context.json"
    path.write_text(json.dumps(document("Alpha"), indent=2) + "\n")
    command = "run threat-model:import " + json.dumps({
        "path": str(path), "label": "Alpha", "activate": False})
    (evidence / "alpha-command.txt").write_text(command)


def verify(root, evidence, stage):
    state = root / ".kuzushi/v3"
    events = [json.loads(line) for line in (state / "workflow/phase-attempts.jsonl").read_text().splitlines()]
    maps = [event for event in events if event.get("event") == "phase_attempt_completed"
            and event.get("phase") == "map"]
    assert len(maps) == 1, "Exactly one actual TUI import must produce this Map"
    run_id = maps[0]["runRefs"][-1]
    output = json.loads((state / "runs" / run_id / "result.json").read_text())
    reference = output["data"]["modelRef"]
    assert output["data"]["snapshot"]["snapshotHash"]
    assert output["data"]["document"]["dfd"]["nodes"]
    beta = json.loads((evidence / "active-beta-ref.json").read_text())
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == beta and reference != beta
    run_tools = {json.loads(path.read_text())["tool"]
                 for path in (state / "runs").glob("*/run.json")}
    assert run_tools <= {"context:build", "threat-model:import", "campaign:study", "threat-model:read"}
    with sqlite3.connect((state / "index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for table in ("investigation_work_attempts", "investigation_call_reservations"):
            if table in tables:
                assert connection.execute("select count(*) from " + table).fetchone()[0] == 0
    if stage in ("accepted", "study", "resumed", "missing"):
        dispositions = [event for event in events if event.get("event") == "phase_attempt_disposition_recorded"]
        assert len(dispositions) == 1 and dispositions[0]["disposition"]["kind"] == "selected"
    if stage in ("study", "resumed", "missing"):
        plans = [json.loads(path.read_text()) for path in (state / "campaigns").glob("*/plan.json")]
        assert len(plans) == 1 and plans[0]["trialsPlanned"] == 3
        assert plans[0]["baseInput"]["threatModelRef"] == reference
        assert plans[0]["workers"] == 1
        assert not (state / "campaigns" / plans[0]["campaignId"] / "queue.json").exists()
    if stage == "resumed":
        ansi = next(evidence.glob("*-resumed-map.ansi")).read_text()
        for sgr in re.findall(r"\x1b\[([\d;]*)m", ansi):
            assert not any(30 <= int(code) <= 38 or 40 <= int(code) <= 48 or 90 <= int(code) <= 107
                           for code in sgr.split(";") if code)
    (evidence / (stage + "-receipt.json")).write_text(json.dumps({
        "source": "labeled imported context; actual local tools and TUI acceptance",
        "stage": stage, "runId": run_id, "mapContext": reference,
        "activeContext": beta, "providerCalls": 0, "discoveryJobsStarted": 0,
    }, indent=2) + "\n")
    return reference


def remove_object(root, evidence):
    reference = verify(root, evidence, "resumed")
    objects = root / ".kuzushi/threat-models/objects"
    candidate = objects / ("sha256-" + reference["sha256"].removeprefix("sha256:") + ".json")
    assert candidate.is_file(), "Remove only the explicitly identified fixture object"
    candidate.unlink()


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "seed":
        seed(root, evidence)
    elif action == "remove":
        remove_object(root, evidence)
    else:
        verify(root, evidence, action)
