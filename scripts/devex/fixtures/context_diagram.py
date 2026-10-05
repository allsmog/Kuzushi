"""Import labeled diagram contexts and authenticate a selected offline study."""
import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from context_comparison import run_tool


def document(label):
    return {
        "version": "1", "methodology": "stride", "title": "Labeled diagram " + label,
        "systemContext": "An offline fixture receives a request and records one item.",
        "summary": {}, "threats": [], "assets": [],
        "dfd": {
            "nodes": [
                {"id": "client", "name": label + " client", "type": "external_entity", "trustZone": "public"},
                {"id": "api", "name": label + " receiver", "type": "process", "trustZone": "application",
                 "description": "Receives one selected item from the caller.", "purpose": "Records the fixture input for later inspection."},
                {"id": "store", "name": label + " records", "type": "data_store", "trustZone": "application"},
            ],
            "flows": [
                {"id": "request", "description": "Selected input", "sourceId": "client", "targetId": "api", "trustBoundaryIds": ["edge"]},
                {"id": "record", "description": "Stored item", "sourceId": "api", "targetId": "store", "trustBoundaryIds": []},
            ],
            "trustBoundaries": [{"id": "edge", "name": "Request boundary", "innerZone": "application", "outerZone": "public", "crossingFlowIds": ["request"]}],
        },
        "attackSurface": {
            "entryPoints": [{"id": "AS-input", "targetElementIds": ["api", "request"], "name": "Recorded input",
                             "description": "Labeled fixture evidence. This is not a production security finding.",
                             "evidence": "reader.py:1", "path": "reader.py", "line": 1}],
            "roleGates": [], "externalSinks": [], "trustedCallers": [],
        },
    }


def seed(root, evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    (root / "reader.py").write_text('print("Labeled diagram fixture")\n')
    refs = {}
    for key, label in [("selected", "Alpha"), ("active", "Beta")]:
        run_tool(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, "import-" + key,
                 "threat-model:import", {"document": document(label), "label": label, "activate": True})
        refs[key] = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())["active"]
    (evidence / "context-refs.json").write_text(json.dumps(refs, indent=2))


def verify(root, evidence, stage):
    refs = json.loads((evidence / "context-refs.json").read_text())
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == refs["active"], "Diagram inspection must not activate another context"
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    assert len(plans) == 1
    plan = plans[0]
    assert plan["baseInput"]["threatModelRef"] == refs["selected"]
    assert plan["trialsPlanned"] == 3 and plan["baseInput"]["tasks"] == ["secret-scan"]
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_work_attempts", "investigation_call_reservations"]:
            if table in tables:
                assert connection.execute("select count(*) from " + table).fetchone()[0] == 0
    if stage == "resumed":
        ansi = next(evidence.glob("*-recovered-diagram.ansi")).read_text()
        for sgr in re.findall(r"\x1b\[([\d;]*)m", ansi):
            assert not any(30 <= int(code) <= 38 or 40 <= int(code) <= 48 or 90 <= int(code) <= 107 for code in sgr.split(";") if code), "No-color restart emitted color"
    (evidence / (stage + "-check.json")).write_text(json.dumps({"campaignId": plan["campaignId"], "selected": refs["selected"], "active": manifest["active"], "jobsStarted": 0, "providerCalls": 0}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "seed":
        seed(root, evidence)
    else:
        verify(root, evidence, action)
