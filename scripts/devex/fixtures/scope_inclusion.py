"""Owned scope metadata, explicit inclusion and immutable plans. No jobs run."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def native(root, evidence, name, tool, value):
    env = dict(os.environ, HOME=str(evidence / "home"))
    for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "NODE_OPTIONS"]:
        env.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", tool, "--input", json.dumps(value)], env=env, capture_output=True, text=True, timeout=35)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    (evidence / (name + ".stdout.txt")).write_text(result.stdout)
    assert result.returncode == 0, (name, result.stderr)
    value = json.loads(result.stdout)
    save(evidence, name, value)
    return value["data"]


def source(root):
    return {name:hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ["auth/login.rs", "server/router.rs ", "README.md"]}


def seed(root, evidence, home):
    assert root.name == "fixture-target"
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    for name in ["auth", "server"]:
        (root / name).mkdir(exist_ok=True)
    for name in ["auth/login.rs", "server/router.rs ", "README.md"]:
        (root / name).write_text("Owned inert scope fixture. Never compiled or executed.\n")
    home.mkdir(parents=True, exist_ok=True)
    save(evidence, "source-before", source(root))
    (evidence / "include-path.txt").write_text("server/router.rs ")
    scopes = [{"id":identity,"name":name,"paths":paths,"rationale":"Owned boundary",
        "sharedDependencies":[],"openQuestions":[]} for identity,name,paths in
        [("auth","Authentication",["auth"]),("rest","Repository files",["README.md","server"])]]
    native(root, evidence, "initial-scopes", "pack:scopes", {"draft":{"schemaVersion":1,
        "scopes":scopes,"sharedDiscovery":False,"exclusions":[{"path":"server/router.rs ","reason":"Defer the owned router file"}]}})


def latest(root, evidence, name):
    return native(root, evidence, name, "pack:scopes", {"operation":"latest"})["review"]


def whole(root, evidence):
    review = latest(root, evidence, "whole-scopes")
    assert review["reference"]["revision"] == 2
    assert review["record"]["draft"]["scopes"][0]["id"] == "repository"
    assert review["record"]["draft"]["exclusions"] == [{"path":"server/router.rs ","reason":"Defer the owned router file"}]
    assert review["coverage"]["discoveryMembers"]["repository"]["total"] == 2
    assert review["coverage"]["excludedFiles"]["total"] == 1
    assert review["record"]["acceptance"] is None
    verify(root, evidence)


def plan(root, evidence, first):
    plans = sorted((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    expected = 1 if first else 2
    assert len(plans) == expected, [str(p) for p in plans]
    old = None if first else json.loads((evidence / "original-plan.json").read_text())
    path = plans[0] if first else next(p for p in plans if str(p) != old["path"])
    document = json.loads(path.read_text())
    assert len(document["jobs"]) == 3 and document["workers"] == 1
    reference = document["baseInput"]["scanScopeRef"]["proposal"]
    assert reference["revision"] == (3 if first else 5)
    files = native(root, evidence, "first-members" if first else "second-members", "pack:scopes", {
        "operation":"files","proposalRef":reference,"fileFilter":{"kind":"scope","scopeId":"repository"}})
    assert files["files"] == (["README.md","auth/login.rs"] if first else ["README.md","auth/login.rs","server/router.rs "])
    if first:
        status = native(root, evidence, "first-plan-status", "campaign:status", {"campaignId":document["campaignId"]})
        native(root, evidence, "first-plan-approval", "campaign:approve-allowance", {
            "investigationId":document["investigationId"],"expectedRevision":0,"model":"openai-codex:gpt-5.5",
            "maxProviderCalls":1,"protectedReviewCalls":1,"reason":"Offline scope history test; no jobs start",
            "campaignId":document["campaignId"],"campaignPlanSha256":status["planSha256"],
            "campaignJobs":3,"maxJobAttempts":1})
        save(evidence, "original-plan", {"path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"campaignId":document["campaignId"],"reference":reference})
    else:
        assert hashlib.sha256(Path(old["path"]).read_bytes()).hexdigest() == old["sha256"]
        native(root, evidence, "historical-export", "workspace:export-findings", {
            "format":"json","output":".kuzushi/reports/original-scope.json","campaignId":old["campaignId"],"allowEmpty":True})
        report = json.loads((root / ".kuzushi/reports/original-scope.json").read_text())["metadata"]["investigation"]
        assert report["scope"]["acceptedScopeProposal"]["coverage"]["excludedFiles"]["total"] == 1
        assert report["occurrence"]["pending"] == 3 and report["observationCount"] == 0
        save(evidence, "new-plan", {"path":str(path),"reference":reference,"jobCount":3})
    verify(root, evidence)


def included(root, evidence):
    review = latest(root, evidence, "included-scopes")
    assert review["reference"]["revision"] == 4
    assert review["coverage"]["excludedFiles"]["total"] == 0
    assert review["coverage"]["discoveryMembers"]["repository"]["total"] == 3
    assert review["record"]["acceptance"] is None
    verify(root, evidence)


def verify(root, evidence):
    assert source(root) == json.loads((evidence / "source-before.json").read_text())
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    counts = {}
    path = root / ".kuzushi/v3/index.sqlite3"
    if path.exists():
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
            tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            for name in ["finding_observations","review_decisions","investigation_work_attempts","investigation_call_reservations"]:
                counts[name] = db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
    assert all(value == 0 for value in counts.values()), counts
    save(evidence, "verified", {"counts":counts,"sourceUnchanged":True,"jobsStarted":0,"providerRequests":0})


root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
stage = sys.argv[3]
if stage == "seed":
    seed(root, evidence, Path(sys.argv[4]).resolve())
elif stage == "whole":
    whole(root, evidence)
elif stage == "first-plan":
    plan(root, evidence, True)
elif stage == "included":
    included(root, evidence)
elif stage == "second-plan":
    plan(root, evidence, False)
else:
    verify(root, evidence)
