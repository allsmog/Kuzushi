"""Saved scope-response replay through real finite native scans. No live model."""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

from installed_scope_study import native, save
from retained_scope_reader import immutable_files
from semgrep_invocation_probe import install

REPO = Path(__file__).resolve().parents[3]
CONTROL = REPO / "scripts/devex/artifacts/scope-balanced-refinement-current-20261026/control"
COMPONENTS = ["control-panel", "gateway", "accounts", "invoicing", "worker", "notifications"]
MARKERS = {"control-panel": "apps/control-panel/unit_095.ts",
           **{name: "services/" + name + "/unit_095.py" for name in COMPONENTS[1:]},
           "loose": "loose.py", "shared": "shared/contracts/message_07.json"}


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def retained():
    prepared, live = read(CONTROL / "prepared.json"), read(CONTROL / "live-result.json")
    root = Path(prepared["target"])
    record = read(root / ".kuzushi/v3/scan-scopes/revisions" / (live["scopeReference"]["recordHash"] + ".json"))
    assert record["revision"] == 3 and record["acceptance"] is None
    return root, prepared, live, record


def source_hashes(root, names):
    return {name: digest(root / name) for name in names}


def seed_sources(root, evidence):
    original, prepared, live, record = retained()
    before = read(REPO / "scripts/devex/artifacts/retained-scope-investigation-current-20261027/control/original-before.json")
    names = [name for name in before if not name.startswith((".kuzushi/", ".git/"))]
    assert len(names) == 602
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    for name in names:
        source = original / name
        assert not Path(name).is_absolute() and ".." not in Path(name).parts
        assert source.resolve().is_relative_to(original.resolve()) and not source.is_symlink()
        assert digest(source) == before[name]
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    save(evidence, "source-before", source_hashes(root, names))
    save(evidence, "original-immutable-before", immutable_files(original, prepared, live))
    save(evidence, "saved-scope-draft", record["draft"])
    reference = record["generation"]["contextRef"]
    doc = read(original / ".kuzushi/threat-models/objects" / ("sha256-" + reference["sha256"].removeprefix("sha256:") + ".json"))
    doc["title"] = "Owned scope response replay context"
    doc["systemContext"] = "SCOPE_RESPONSE_REPLAY_WORKFLOW. " + doc["systemContext"]
    (root / ".kuzushi").mkdir(exist_ok=True)
    save(root / ".kuzushi", "replay-context", doc)


def seed_home(evidence, home):
    subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(home)], check=True)
    provider = evidence / "provider.mjs"
    shutil.copyfile(REPO / "scripts/devex/fixtures/scope_replay_provider.mjs", provider)
    credential = home / ".kuzushi/replay-credentials.json"
    credential.parent.mkdir(parents=True, exist_ok=True)
    credential.write_text(json.dumps({"openai-codex": {"access": "offline-scope-replay-fixture", "expires": 99999999999999}}))
    credential.chmod(0o600)
    command = ["env", "PATH=" + str(Path(os.environ["KUZUSHI_NATIVE_BIN"]).resolve().parent) + os.pathsep + os.environ["PATH"],
               "node", "--import", str(provider), str(REPO / "scripts/langgraph-bridge.mjs")]
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-6-luna"\n[runtime]\nthinking_level = "low"\nlanggraph_bridge_command = '
                      + json.dumps(command) + '\n[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credential)) + '\nallow_env_token = false\n')
    (evidence / "runtime-home.txt").write_text(str(home))


def seed(root, evidence, home):
    seed_sources(root, evidence)
    seed_home(evidence, home)
    rules = evidence / "local-rules.yaml"
    rules.write_text('rules:\n  - id: owned-replayed-scope-marker\n    languages: [generic]\n    severity: INFO\n    message: Owned replay policy marker needs an owner decision\n    paths:\n      include:\n        - "**/unit_095.ts"\n        - "**/unit_095.py"\n        - loose.py\n        - shared/contracts/message_07.json\n    pattern-regex: "Owned inert architecture fixture|Owned inert root integration source|Owned message format 7"\n  - id: owned-replay-all-source-coverage\n    languages: [generic]\n    severity: INFO\n    message: Owned coverage-only fixture rule\n    pattern-regex: "CONTROLLED_REPLAY_NEVER_PRESENT_93d3ed18"\n')
    (evidence / "rule-setting.txt").write_text("set semgrepConfig " + json.dumps([str(rules)]))
    (evidence / "scanner-setting.txt").write_text("set semgrepBinary " + json.dumps(str(install(evidence))))
    (evidence / "priorities.txt").write_text("Controlled saved scope response replay.\nPreserve services, shared context and all loose root files. No fresh model-quality result is requested.")


def plans(root):
    return [read(path) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]


def jobs(root, plan):
    path = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
    return read(path)["jobs"] if path.exists() else {}


def wait_completed(root, plan):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        rows = jobs(root, plan)
        if rows and all(row["state"] in ["completed", "failed", "parked"] for row in rows.values()):
            assert all(row["state"] == "completed" for row in rows.values()), rows
            return rows
        time.sleep(0.2)
    raise AssertionError("Owned finite jobs did not complete within the experiment deadline")


def scope_review(root, evidence):
    return native(root, evidence, "scope-latest", ["run", "pack:scopes", "--input", '{"operation":"latest"}'])["data"]["review"]


def proposal(root, evidence, stage):
    entries = plans(root)
    matches = [plan for plan in entries if plan.get("tool") == "pack:suggest-scopes"]
    assert len(matches) == 1
    plan = matches[0]
    assert plan["workers"] == 1 and len(plan["jobs"]) == 1
    assert plan["model"] == "openai-codex:gpt-6-luna"
    log = evidence / "scope-replay-calls.jsonl"
    if stage == "proposal-draft":
        assert not log.exists() and not jobs(root, plan)
        return
    rows = wait_completed(root, plan)
    assert len(rows) == 1 and all(row["attempts"] == 1 for row in rows.values())
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(calls) == 1 and calls[0]["replySha256"] == digest(evidence / "saved-scope-draft.json")
    review = scope_review(root, evidence)
    assert review["record"]["draft"] == read(evidence / "saved-scope-draft.json")
    assert review["reference"] != read(CONTROL / "live-result.json")["scopeReference"]
    assert review["record"]["generation"]["runId"] == next(iter(rows.values()))["runId"]
    coverage = review["coverage"]
    assert coverage["enumeratedFiles"] == 602 and coverage["enumerationComplete"]
    assert coverage["uncoveredFiles"]["total"] == coverage["overlaps"]["total"] == 0
    assert len(coverage["discoveryMembers"]) == 7 and coverage["contextMembers"]["shared-contracts"]["total"] == 8
    if stage == "accepted":
        assert review["record"]["acceptance"] is not None
        save(evidence, "accepted-scopes", review)
    else:
        assert review["record"]["acceptance"] is None
    save(evidence, stage + "-check", {"scopes": 7, "members": 602, "interceptedReplies": 1, "liveProviderRequests": 0})


def scan_plan(root, evidence):
    entries = [plan for plan in plans(root) if plan["kind"] == "scope-study"]
    assert len(entries) == 1
    plan = entries[0]
    accepted = read(evidence / "accepted-scopes.json")
    scope_job = next(plan for plan in plans(root) if plan.get("tool") == "pack:suggest-scopes")
    assert plan["investigationId"] == scope_job["investigationId"]
    assert plan["workers"] == 1 and plan["jobCount"] == len(plan["jobs"]) == 21
    assert plan["scopeStudy"]["unplannedScopeIds"] == []
    cases = {case["id"]: case for case in plan["scopeStudy"]["cases"]}
    assert set(cases) == set(COMPONENTS) | {"integration-residual"}
    common = plan["scopeStudy"]["inheritedThreatModelRef"]
    assert common and common == accepted["record"]["generation"]["contextRef"]
    for case in cases.values():
        scan = case["baseInput"]
        assert case["passes"] == 3 and case["equivalence"]["components"].get("model") is None
        assert scan["scanScopeRef"]["proposal"] == accepted["reference"] and scan["threatModelRef"] == common
        assert scan["tasks"] == ["semgrep"] and scan["semgrepTimeoutMs"] == 60000
        assert all(not scan[key] for key in ["triage", "verify", "patch", "autoPatch", "pocExecution", "dynamicAnalysis"])
    (evidence / "resume-scan.txt").write_text("campaign " + plan["campaignId"])
    return plan, cases


def native_membership(root, evidence, cases):
    accepted = read(evidence / "accepted-scopes.json")
    source = set(read(evidence / "source-before.json"))
    groups = {scope["id"]: {name for name in source if any(name == path or name.startswith(path + "/")
              for path in scope["paths"])} for scope in accepted["record"]["draft"]["scopes"]}
    assert {name: len(group) for name, group in groups.items()} == {name: (14 if name == "integration-residual" else 98) for name in groups}
    expected = {name for group in groups.values() for name in group}
    rows = [json.loads(line) for line in (evidence / "semgrep-invocations.jsonl").read_text().splitlines()]
    scans = [row for row in rows if "--" in row["argv"]]
    counts, workers = Counter(), {}
    for row in scans:
        args = row["argv"]
        assert Path(row["cwd"]).resolve() == root.resolve()
        assert "--json" in args and args[args.index("--metrics") + 1] == "off"
        files = args[args.index("--") + 1:]
        assert 0 < len(files) <= 1024 and len(files) == len(set(files))
        encoded_bytes = len(os.fsencode(str(evidence / "semgrep-probe"))) + 1
        encoded_bytes += sum(len(os.fsencode(arg)) + 1 for arg in args)
        assert encoded_bytes <= 12288
        assert set(files) <= expected and sum(set(files) <= group for group in groups.values()) == 1
        counts.update(files)
        workers.setdefault(row["parentPid"], []).extend(files)
    assert counts == Counter({name: 3 for name in expected}) and len(workers) == 21
    for files in workers.values():
        assert len(files) == len(set(files)) and set(files) in groups.values()
    save(evidence, "native-membership", {"filesSubmitted": len(expected), "executorProcesses": len(workers),
         "scannerProcesses": len(scans), "passesPerFile": 3, "sourceExecuted": False,
         "ruleCoverage": "Eight explicitly selected benign markers; no complete security coverage claim"})


def completed(root, evidence, plan, cases):
    rows = wait_completed(root, plan)
    assert len(rows) == 21 and all(row["attempts"] == 1 for row in rows.values())
    native_membership(root, evidence, cases)
    occurrence = native(root, evidence, "scope-occurrence", ["findings", "batch", plan["campaignId"], "--json"])
    found = set()
    for case in occurrence["cases"]:
        value = case["occurrence"]
        assert value["planned"] == value["completed"] == 3 and value["failed"] == value["pending"] == 0
        assert len(value["rows"]) == (2 if case["id"] == "integration-residual" else 1)
        for row in value["rows"]:
            assert row["seen"] == 3
            path = row["representativeLocation"].rsplit(":", 1)[0]
            name = next(name for name, expected in MARKERS.items() if path.endswith(expected))
            found.add(name)
            (evidence / ("open-" + name + ".txt")).write_text("open " + row["representativeFingerprint"])
    assert found == set(MARKERS)


def exported(root, evidence, plan, stage):
    path = root / ".kuzushi/reports/findings.json"
    data = path.read_bytes()
    if stage == "restarted":
        assert data == (evidence / "export-before-restart.json").read_bytes()
    else:
        (evidence / "export-before-restart.json").write_bytes(data)
    report = json.loads(data)
    assert report["count"] == 8 and all(row["reviewDecision"] == "deferred" for row in report["findings"])
    receipt = report["metadata"]["investigation"]
    assert receipt["campaignId"] == plan["campaignId"] and receipt["observationCount"] == 24
    assert receipt["reviewedCount"] == 8 and receipt["confirmedCount"] == 0
    assert receipt["unplannedScopeIds"] == [] and len(receipt["scope"]) == 7
    budget = receipt["allowance"]["currentInvestigation"]
    assert budget["committedCalls"] == 1 and budget["unresolvedCalls"] == 0
    assert budget["limits"] == {"maxProviderCalls": 3, "protectedReviewCalls": 2}


def verify(root, evidence, stage):
    before = read(evidence / "source-before.json")
    assert source_hashes(root, before) == before
    assert all(digest(Path(name)) == value for name, value in read(evidence / "original-immutable-before.json").items())
    manifest = root / ".kuzushi/threat-models/manifest.json"
    assert read(manifest).get("active") is None
    if stage.startswith("proposal-") or stage == "accepted":
        proposal(root, evidence, stage)
    else:
        plan, cases = scan_plan(root, evidence)
        if stage != "scan-draft":
            completed(root, evidence, plan, cases)
        if stage in ["exported", "restarted"]:
            exported(root, evidence, plan, stage)
        save(evidence, stage + "-check", {"jobs": 21, "interceptedReplies": 1, "liveProviderRequests": 0, "sourceExecuted": False})


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, stage)
