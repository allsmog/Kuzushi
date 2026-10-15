"""Edit a copy of the real proposal; preserve the original live receipts."""
import hashlib
import json
import shutil
import sys
from pathlib import Path

from installed_scope_study import current_counts, native, save

LIVE = Path("/private/tmp/kuzushi-live-monorepo-scope-20261014")
RUN = "live-scope-proposal-references-20261014-context-001-a1"


def hashes(root, names):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}


def live_receipts():
    state = LIVE / "target/.kuzushi/v3"
    return {str(path.relative_to(state)): hashlib.sha256(path.read_bytes()).hexdigest()
            for directory in ["runs", "campaigns", "scan-scopes"]
            for path in (state / directory).rglob("*") if path.is_file()}


def seed(root, evidence, home):
    assert root.name == "fixture-target" and root.parent == evidence
    source = json.loads((LIVE / "control/source-before.json").read_text())
    assert len(source) == 9 and hashes(LIVE / "target", source) == source
    for name in ["app.py", "config.env"]:
        (root / name).unlink()
    for name in source:
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(LIVE / "target" / name, destination)
    home.mkdir(parents=True, exist_ok=True)
    (evidence / "runtime-home.txt").write_text(str(home))
    save(evidence, "source-before", source)
    (evidence / "greeting-members.txt").write_text("crates/greeting/Cargo.toml\ncrates/greeting/src/lib.rs")
    save(evidence, "original-live-receipts", live_receipts())
    result = json.loads((LIVE / "target/.kuzushi/v3/runs" / RUN / "result.json").read_text())["data"]
    value = native(root, evidence, "copied-draft", ["run", "pack:scopes", "--input",
        json.dumps({"operation":"create", "draft":result["record"]["draft"]})])["data"]
    assert value["record"].get("generation") is None
    assert value["coverage"]["uncoveredFiles"]["total"] == 2
    save(evidence, "initial-scopes", value)


def current(root, evidence, stage):
    source = json.loads((evidence / "source-before.json").read_text())
    assert hashes(root, source) == source == hashes(LIVE / "target", source)
    assert live_receipts() == json.loads((evidence / "original-live-receipts.json").read_text())
    assert all(value in [None, 0] for value in current_counts(root, evidence).values())
    value = native(root, evidence, stage, ["run", "pack:scopes", "--input", '{"operation":"latest"}'])["data"]["review"]
    initial = json.loads((evidence / "initial-scopes.json").read_text())
    assert value["record"]["draft"]["sharedScope"] == initial["record"]["draft"]["sharedScope"]
    assert not value["record"]["draft"]["sharedDiscovery"]
    if stage == "invalid":
        assert value == initial
    else:
        assert len(value["record"]["draft"]["scopes"]) == 4
        assert value["coverage"]["uncoveredFiles"]["total"] == value["coverage"]["overlaps"]["total"] == 0
        added = value["record"]["draft"]["scopes"][-1]
        assert added["name"] == "Greeting discovery"
        assert added["paths"] == ["crates/greeting/Cargo.toml", "crates/greeting/src/lib.rs"]
        assert value["coverage"]["discoveryMembers"][added["id"]]["total"] == 2
        assert (value["record"]["acceptance"] is not None) == (stage in ["accepted", "planned", "restarted"])
    save(evidence, stage + "-check", {"reference":value["reference"], "coverage":value["coverage"],
        "sourceExecuted":False, "providerCalls":0, "originalLiveReceiptsUnchanged":True})
    return value


def prepare(root, evidence):
    review = current(root, evidence, "accepted")
    cases = [{"scopeId":scope["id"]} for scope in review["record"]["draft"]["scopes"]]
    value = native(root, evidence, "prepared-study", ["run", "campaign:study", "--input", json.dumps({
        "campaignId":"owned-added-scope-study", "scopeProposalRef":review["reference"], "scopeCases":cases,
        "scanInput":{"taskMode":"manual", "tasks":["secret-scan"], "threatModelRef":None, "scanContextRef":None}})])["data"]
    assert value["jobCount"] == 12 and value["workers"] == 1
    assert value["scopeStudy"]["unplannedScopeIds"] == []
    plan = json.loads(Path(value["planPath"]).read_text())
    assert len(plan["jobs"]) == 12 and len(plan["scopeStudy"]["cases"]) == 4
    assert all(job["input"]["scanScopeRef"]["proposal"] == review["reference"] for job in plan["jobs"])
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    save(evidence, "fixed-plan", plan)
    current(root, evidence, "planned")


if __name__ == "__main__":
    root, evidence, home = [Path(value).resolve() for value in sys.argv[1:4]]
    stage = sys.argv[4]
    if stage == "seed": seed(root, evidence, home)
    elif stage == "prepare": prepare(root, evidence)
    else: current(root, evidence, stage)
