"""Recorded human job labels and inspection over a copy of the live scope draft."""
import hashlib
import json
import sys
from pathlib import Path

import scope_addition
from installed_scope_study import native, save

CAMPAIGN = "owned-added-scope-study"


def seed(root, evidence, home):
    scope_addition.seed(root, evidence, home)
    original = json.loads((evidence / "initial-scopes.json").read_text())
    added = native(root, evidence, "add-membership", ["run", "pack:scopes", "--input", json.dumps({
        "operation":"edit", "proposalRef":original["reference"], "edit":{"action":"add-scope", "scope":{
            "id":"greeting-discovery", "name":"Greeting discovery", "paths":["crates/greeting/Cargo.toml", "crates/greeting/src/lib.rs"],
            "rationale":"Explicit greeting implementation review with separate shared context.", "sharedDependencies":[], "openQuestions":[]}}})])["data"]
    native(root, evidence, "accept-membership", ["run", "pack:scopes", "--input", json.dumps({
        "operation":"accept", "proposalRef":added["reference"], "acknowledgements":{
            "inventoryLimitations":True, "overlappingDiscovery":False, "exclusions":False}})])
    scope_addition.prepare(root, evidence)
    save(evidence, "plan-before", plan_hash(root))
    verify(root, evidence, "seeded")


def plan_hash(root):
    return hashlib.sha256((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "plan.json").read_bytes()).hexdigest()


def verify(root, evidence, stage):
    scope_addition.current(root, evidence, "planned")
    assert plan_hash(root) == json.loads((evidence / "plan-before.json").read_text())
    value = native(root, evidence, stage + "-status", ["run", "campaign:status", "--input", json.dumps({"campaignId":CAMPAIGN})])["data"]
    jobs = value["jobs"]
    assert len(jobs) == 12 and value["states"] == {"planned":12}
    expected = [f"{name} · pass {trial}/3" for name in ["Hello CLI", "Wave CLI", "Root integration and residual files", "Greeting discovery"] for trial in range(1,4)]
    assert [job["displayLabel"] for job in jobs] == expected
    assert all(job["attempts"] == 0 and job["runId"] is None for job in jobs)
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    save(evidence, stage + "-reader-check", {"recordedLabels":expected,"plannedJobs":12,"startedJobs":0,
        "providerCalls":0,"sourceExecuted":False,"planUnchanged":True,"originalLiveReceiptsUnchanged":True})


if __name__ == "__main__":
    root, evidence, home = [Path(value).resolve() for value in sys.argv[1:4]]
    stage = sys.argv[4]
    if stage == "seed": seed(root, evidence, home)
    else: verify(root, evidence, stage)
