"""Owned operator briefs and exact finite-plan association; no model or scanner work."""
import hashlib
import json
import os
from secret_settings import ledger
import subprocess
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def native(root, evidence, name, tool, value, succeeds=True):
    env = dict(os.environ, HOME=str(evidence / "home"))
    for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "NODE_OPTIONS"]:
        env.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", tool, "--input", json.dumps(value)], env=env, capture_output=True, text=True, timeout=35)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    (evidence / (name + ".stdout.txt")).write_text(result.stdout)
    assert (result.returncode == 0) == succeeds, (name, result.stderr)
    value = json.loads(result.stdout)
    save(evidence, name, value)
    return value


def source(root):
    return {name:hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ["package.json", "main.rs"]}


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "package.json").write_text('{"name":"owned-brief-policy","private":true}\n')
    (root / "main.rs").write_text("// Owned inert metadata. Never compiled or executed.\n")
    home.mkdir(parents=True, exist_ok=True)
    text = "Goal\nReview package policy for the owned repository.\n\nPriorities\nKeep owner decisions and evidence separate. 東京 notes remain readable.\n\nOpen questions\nWho owns the package license declaration?\n"
    (evidence / "brief-text.txt").write_text(text)
    (evidence / "brief-addition.txt").write_text("\nSecond revision\nRetain the original plan's exact goals.\n")
    save(evidence, "source-before", source(root))


def current(root, evidence, name):
    result = native(root, evidence, name, "campaign:brief", {})
    assert result["data"]["modelRequests"] == 0 and result["data"]["workApproved"] is False
    return result["data"]["brief"]


def first(root, evidence):
    brief = current(root, evidence, "first-brief")
    assert brief["reference"]["revision"] == 1
    assert brief["document"]["text"] == (evidence / "brief-text.txt").read_text()
    native(root, evidence, "stale-brief", "campaign:brief", {"mode":"save","expectedRevision":0,"text":"Stale goal"}, False)
    native(root, evidence, "unknown-brief-option", "campaign:brief", {"unknown":True}, False)
    native(root, evidence, "large-brief", "campaign:brief", {"mode":"save","expectedRevision":1,"text":"x" * 8193}, False)
    draft = native(root, evidence, "brief-plan", "campaign:study", {"campaignId":"brief-bound","investigationId":"brief-accounting",
        "briefRef":brief["reference"],"scanInput":{"taskMode":"manual","tasks":["license-scan"],"threatModelRef":None}})
    assert draft["data"]["jobCount"] == 3 and draft["data"]["workers"] == 1
    path = root / ".kuzushi/v3/campaigns/brief-bound/plan.json"
    plan = json.loads(path.read_text())
    assert plan["investigationBrief"] == brief and "briefRef" not in plan["baseInput"]
    assert all("briefRef" not in job["input"] for job in plan["jobs"])
    native(root, evidence, "brief-plan-approval", "campaign:approve-allowance", {"investigationId":"brief-accounting","expectedRevision":0,
        "model":"openai-codex:gpt-5.5","maxProviderCalls":1,"protectedReviewCalls":1,"reason":"Owned offline plan association; no work starts",
        "campaignId":"brief-bound","campaignPlanSha256":draft["data"]["planSha256"],"campaignJobs":3,"maxJobAttempts":1})
    save(evidence, "frozen-plan", {"sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"brief":brief,"jobs":plan["jobs"]})
    (evidence / "exact-brief-command.txt").write_text("run campaign:brief " + json.dumps({"mode":"read","briefRef":brief["reference"]}))


def revised(root, evidence):
    brief = current(root, evidence, "second-brief")
    assert brief["reference"]["revision"] == 2
    expected = (evidence / "brief-text.txt").read_text() + (evidence / "brief-addition.txt").read_text()
    assert brief["document"]["text"] == expected
    frozen = json.loads((evidence / "frozen-plan.json").read_text())
    path = root / ".kuzushi/v3/campaigns/brief-bound/plan.json"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == frozen["sha256"]
    assert brief["document"]["previous"] == frozen["brief"]["reference"]
    exact = native(root, evidence, "old-exact-brief", "campaign:brief", {"briefRef":frozen["brief"]["reference"]})
    assert exact["data"]["brief"] == frozen["brief"]
    verify(root, evidence)


def verify(root, evidence):
    assert source(root) == json.loads((evidence / "source-before.json").read_text())
    path = root / ".kuzushi/v3/index.sqlite3"
    counts = {}
    if path.exists():
        with ledger(root,evidence) as db:
            tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
                counts[name] = db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
    assert all(value == 0 for value in counts.values()), counts
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    save(evidence, "verified", {"counts":counts,"sourceUnchanged":True,"jobsStarted":0,"providerRequests":0,"activeThreatModelChanged":False})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "first":
        first(root, evidence)
    elif stage == "revised":
        revised(root, evidence)
    else:
        verify(root, evidence)
