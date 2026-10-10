"""Owned imported guidance receipts. Model use is unverified; no jobs run."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native(root, evidence, name, tool, value):
    env = dict(os.environ, HOME=str(evidence / "home"))
    for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "NODE_OPTIONS"]:
        env.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root), "run", tool,
        "--input", json.dumps(value)], env=env, capture_output=True, text=True, timeout=35)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, (name, result.stderr)
    response = json.loads(result.stdout)
    save(evidence, name, response)
    return response["data"]


def document(title):
    return {"version":"1", "methodology":"stride", "title":title,
        "systemContext":"Owned imported architecture notes. Guidance model use is unverified.",
        "dfd":{"nodes":[{"id":"greeting", "name":"Greeting", "type":"process", "trustZone":"internal"}],
            "flows":[], "trustBoundaries":[]}, "threats":[], "summary":{},
        "openQuestions":["Who owns this component?"]}


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "main.rs").write_text("// Owned greeting notes. Never compiled or executed.\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    text = "Original architecture priorities\nExplain the owned greeting.\n\nOwner questions\n東京 notes stay exact. Who owns this component?\n"
    first = native(root, evidence, "first-goal", "campaign:brief", {"mode":"save", "expectedRevision":0, "text":text})["brief"]
    old = document("Historical imported context")
    old["provenance"] = {"operatorIntent":{"schemaVersion":1, "reference":first["reference"],
        "textBytes":len(text.encode()), "purpose":"architecture priorities and open questions",
        "sourceEvidence":False, "findingAuthority":False}}
    selected = native(root, evidence, "import-old", "threat-model:import", {"activate":True, "label":"Historical", "document":old})["modelRef"]
    native(root, evidence, "second-goal", "campaign:brief", {"mode":"save", "expectedRevision":1, "text":"Later replacement goal"})
    active = native(root, evidence, "import-active", "threat-model:import", {"activate":True, "label":"Current", "document":document("Other active context")})["modelRef"]
    plan = native(root, evidence, "planned", "campaign:study", {"campaignId":"goal-reader", "investigationId":"goal-reader",
        "scanInput":{"taskMode":"manual", "tasks":["license-scan"]}, "baselineCaseId":"historical",
        "contextCases":[{"id":"historical", "label":"Historical context", "threatModelRef":selected},
            {"id":"omitted", "label":"No context", "threatModelRef":None}]})
    native(root, evidence, "approved", "campaign:approve-allowance", {"campaignId":"goal-reader", "investigationId":"goal-reader",
        "expectedRevision":0, "campaignPlanSha256":plan["planSha256"], "campaignJobs":6, "maxJobAttempts":1,
        "model":"openai-codex:gpt-5.5", "maxProviderCalls":1, "protectedReviewCalls":1,
        "reason":"Owned offline reader fixture. No work or model requests."})
    plan_path = root / ".kuzushi/v3/campaigns/goal-reader/plan.json"
    context_path = root / ".kuzushi/threat-models/objects" / ("sha256-" + selected["sha256"].removeprefix("sha256:") + ".json")
    save(evidence, "before", {"selected":selected, "active":active, "goal":first,
        "sourceSha256":sha(root / "main.rs"), "manifestSha256":sha(root / ".kuzushi/threat-models/manifest.json"),
        "planSha256":sha(plan_path), "contextPath":str(context_path), "contextSha256":sha(context_path)})
    verify(root, evidence, "seeded")


def verify(root, evidence, stage):
    before = json.loads((evidence / "before.json").read_text())
    assert sha(root / "main.rs") == before["sourceSha256"]
    assert sha(Path(before["contextPath"])) == before["contextSha256"]
    assert sha(root / ".kuzushi/threat-models/manifest.json") == before["manifestSha256"]
    assert sha(root / ".kuzushi/v3/campaigns/goal-reader/plan.json") == before["planSha256"]
    head = json.loads((root / ".kuzushi/v3/investigation-briefs/repository/head.json").read_text())
    assert head["revision"] == 2
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    counts = {}
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for name in ["finding_observations", "review_decisions", "investigation_work_attempts", "investigation_call_reservations"]:
            counts[name] = db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
    assert all(value == 0 for value in counts.values())
    if stage in ["exported", "restarted"]:
        check_reading(evidence)
        receipts = list((root / ".kuzushi/reports").glob("*.investigation.json"))
        assert len(receipts) == 1
        receipt = json.loads(receipts[0].read_text())
        guidance = receipt["scope"]["caseContextGuidance"]["historical"]
        assert guidance["reference"] == before["goal"]["reference"]
        assert guidance["contextRef"] == before["selected"]
        assert guidance["text"] == before["goal"]["document"]["text"]
        assert guidance["modelUseVerified"] is False and guidance["sourceEvidence"] is False
        assert receipt["scope"]["caseContextGuidance"]["omitted"]["status"] == "omitted"
        assert all(case["occurrence"]["pending"] == 3 and case["occurrence"]["completed"] == 0 for case in receipt["occurrence"]["cases"])
    save(evidence, stage + "-verified", {"counts":counts, "sourceUnchanged":True, "contextUnchanged":True,
        "activeUnchanged":True, "planUnchanged":True, "jobsStarted":0, "providerRequests":0, "modelUseVerified":False})


def check_reading(evidence):
    pages = sorted(evidence.glob("*-report-page-*-40x12.txt"))
    assert len(pages) == 12
    assert len({path.read_text() for path in pages}) >= 10
    text = " ".join(" ".join(path.read_text().replace("│", " ").split()) for path in pages)
    for phrase in ["Original architecture priorities", "東京 notes stay exact.",
        "Model use is not independently verified", "context explicitly omitted"]:
        assert phrase in text, "Report paging did not expose: " + phrase


def availability(root, evidence, restore):
    path = root / ".kuzushi/v3/investigation-briefs/repository/revisions/1.json"
    backup = evidence / "retained-goal-ordinal.json"
    if restore:
        backup.rename(path)
    else:
        path.rename(backup)
    verify(root, evidence, "restored" if restore else "hidden")


def main():
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage in ["hide", "restore"]:
        availability(root, evidence, stage == "restore")
    else:
        verify(root, evidence, stage)


if __name__ == "__main__":
    main()
