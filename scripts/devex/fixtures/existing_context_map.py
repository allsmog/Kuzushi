"""Review real source-bound context without regeneration or provider requests."""
import json
import sys
from pathlib import Path
import map_functionality


def seed(root, evidence, home):
    map_functionality.seed(root, evidence, home)
    first = json.loads((evidence / "map-result.json").read_text())["data"]
    document = first["document"]
    document["title"] = "Other active context: labeled source-only fixture"
    active = map_functionality.execute(root, evidence, home, "other-context", "threat-model:import", {"document": document, "activate": True})
    (evidence / "context-refs.json").write_text(json.dumps({"selected": first["modelRef"], "active": active["modelRef"]}, indent=2))


def verify(root, evidence, stage):
    map_functionality.verify(root, evidence)
    refs = json.loads((evidence / "context-refs.json").read_text())
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == refs["active"], "Map acceptance must preserve global activation"
    events = [json.loads(line) for line in (root / ".kuzushi/v3/workflow/phase-attempts.jsonl").read_text().splitlines() if line]
    completed = [event for event in events if event["event"] == "phase_attempt_completed"]
    decisions = [event for event in events if event["event"] == "phase_attempt_disposition_recorded"]
    assert len(completed) == 1
    assert completed[0]["outcome"] == "partial"
    assert len(decisions) == (0 if stage == "pending" else 1)
    if decisions:
        assert decisions[0]["disposition"]["acknowledged_partial"] is True
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    if stage == "planned":
        assert len(plans) == 1
        plan = plans[0]
        assert plan["baseInput"]["threatModelRef"] == refs["selected"]
        assert plan["trialsPlanned"] == 3 and plan["requestedWorkers"] == 1
        (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    (evidence / (stage + "-check.json")).write_text(json.dumps({"partialMap": True, "accepted": bool(decisions), "activeUnchanged": True, "providerCalls": 0, "sourceUnchanged": True, "plans": len(plans)}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, stage)
