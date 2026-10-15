"""Owned membership transition through real legacy and current executables."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from secret_settings import ledger

LEGACY_SHA = "486cd6f04dd002f626e1004df0f4d54a76c0365ea28fddba332a1c46914129e8"
FILES = ["first.rs", "service/module.rs", "later.rs"]


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def environment(evidence, home):
    env = dict(os.environ, HOME=str(home), GIT_CONFIG_GLOBAL=str(evidence / "git-config"),
               GIT_CONFIG_SYSTEM=str(evidence / "git-config"))
    for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KUZUSHI_MODEL", "NODE_OPTIONS", "KUZUSHI_LANGGRAPH_BRIDGE"]:
        env.pop(key, None)
    return env


def git(root, evidence, home, *arguments):
    return subprocess.check_output(["git", "-C", str(root), "-c", "core.hooksPath=/dev/null",
        "-c", "commit.gpgsign=false", "-c", "user.name=Owned fixture", "-c",
        "user.email=fixture@example.invalid", *arguments], env=environment(evidence, home), text=True).strip()


def native(root, evidence, home, name, tool, inputs, legacy=False, refuses=None):
    binary = os.environ["KUZUSHI_LEGACY_NATIVE_BIN" if legacy else "KUZUSHI_NATIVE_BIN"]
    if legacy:
        assert hashlib.sha256(Path(binary).read_bytes()).hexdigest() == LEGACY_SHA
    result = subprocess.run([binary, "--plain", "--target", str(root), "run", tool, "--input", json.dumps(inputs)],
        env=environment(evidence, home), capture_output=True, text=True, timeout=45)
    (evidence / (name + ".stdout.json")).write_text(result.stdout)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    value = json.loads(result.stdout)
    if refuses:
        assert result.returncode in [2, 3] and value["status"] in ["blocked", "failed"]
        assert refuses in json.dumps(value), value
    else:
        assert result.returncode == 0 and value["status"] == "completed", result.stderr
    return value.get("data")


def hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in FILES}


def seed(root, evidence, home):
    assert root.name == "fixture-target" and root.parent == evidence
    assert {path.name for path in root.iterdir()} == {".git", "app.py", "config.env"}
    shutil.rmtree(root)
    root.mkdir()
    (evidence / "git-config").write_text("")
    (root / "service").mkdir()
    for name in FILES[:2]:
        (root / name).write_text("// Owned source text. Never executed.\n")
    git(root, evidence, home, "init", "--quiet", "--initial-branch=main")
    git(root, evidence, home, "add", *FILES[:2])
    tree = git(root, evidence, home, "write-tree")
    commit = git(root, evidence, home, "commit-tree", tree, "-m", "fixture: record owned membership")
    git(root, evidence, home, "update-ref", "refs/heads/main", commit)
    (root / "later.rs").write_text("// Owned untracked source text. Never executed.\n")
    save(evidence, "source-before", hashes(root))
    save(evidence, "source-identity", {"gitRevision": commit, "gitTree": tree})
    draft = native(root, evidence, home, "legacy-draft", "pack:scopes", {"operation": "create"}, legacy=True)
    accepted = native(root, evidence, home, "legacy-accepted", "pack:scopes", {"operation": "accept",
        "proposalRef": draft["reference"], "acknowledgements": {"inventoryLimitations": False,
        "overlappingDiscovery": False, "exclusions": False}}, legacy=True)
    assert accepted["record"]["source"].get("enumerationHash") is None
    save(evidence, "legacy-review", accepted)


def latest(root, evidence, home, stage):
    return native(root, evidence, home, stage, "pack:scopes", {"operation": "latest"})["review"]


def verify(root, evidence, home, stage):
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    identity = json.loads((evidence / "source-identity.json").read_text())
    assert git(root, evidence, home, "rev-parse", "HEAD") == identity["gitRevision"]
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
            for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]}
        assert not any(counts.values())
    value = latest(root, evidence, home, stage)
    legacy = json.loads((evidence / "legacy-review.json").read_text())
    history = native(root, evidence, home, stage + "-legacy", "pack:scopes",
        {"operation": "read", "proposalRef": legacy["reference"]})
    assert history == legacy
    expected = 2 if stage in ["legacy", "bound", "accepted", "refused"] else 3
    assert value["coverage"]["enumeratedFiles"] == expected
    accepted = stage in ["legacy", "accepted", "refused", "ready", "restarted"]
    assert (value["record"]["acceptance"] is not None) == accepted
    if stage != "legacy":
        assert len(value["record"]["source"]["enumerationHash"]) == 64
    if stage == "accepted":
        save(evidence, "before-staging", value)
    if expected == 3:
        before = json.loads((evidence / "before-staging.json").read_text())
        for key in ["treeHash", "snapshotHash", "gitRevision", "dirty"]:
            assert value["record"]["source"][key] == before["record"]["source"][key]
        assert value["record"]["source"]["enumerationHash"] != before["record"]["source"]["enumerationHash"]
        assert value["record"]["inventoryHash"] != before["record"]["inventoryHash"]
        assert "later.rs" in value["coverage"]["discoveryMembers"]["repository"]["files"]
    save(evidence, stage + "-check", {"reference": value["reference"], "source": value["record"]["source"],
        "files": expected, "sourceBytesPreserved": True, "providerRequests": 0, "sourceExecuted": False,
        "legacyHistoryPreserved": True, "ledgerCounts": counts})
    return value


def study_input(reference, name):
    return {"campaignId": name, "scopeProposalRef": reference, "scopeCases": [{"scopeId": "repository"}],
        "scanInput": {"taskMode": "manual", "tasks": ["secret-scan"], "threatModelRef": None,
        "scanContextRef": None, "triage": False, "verify": False, "autoPatch": False}}


def refuse_plan(root, evidence, home, stage):
    value = verify(root, evidence, home, "legacy" if stage == "legacy-plan" else "refused")
    reason = "predates membership binding" if stage == "legacy-plan" else "inventory membership changed"
    native(root, evidence, home, stage, "campaign:study", study_input(value["reference"], "owned-refused-" + stage), refuses=reason)
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))


def prepare(root, evidence, home):
    value = verify(root, evidence, home, "ready")
    result = native(root, evidence, home, "fixed-study", "campaign:study",
        study_input(value["reference"], "owned-membership-study"))
    assert result["jobCount"] == 3 and result["workers"] == 1
    plan = json.loads(Path(result["planPath"]).read_text())
    assert len(plan["jobs"]) == 3
    assert all(job["input"]["scanScopeRef"]["proposal"] == value["reference"] for job in plan["jobs"])
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    save(evidence, "fixed-plan", plan)


if __name__ == "__main__":
    root, evidence, home = [Path(value).resolve() for value in sys.argv[1:4]]
    stage = sys.argv[4]
    if stage == "seed": seed(root, evidence, home)
    elif stage == "stage-file": git(root, evidence, home, "add", "later.rs")
    elif stage in ["legacy-plan", "staged-plan"]: refuse_plan(root, evidence, home, stage)
    elif stage == "prepare": prepare(root, evidence, home)
    else: verify(root, evidence, home, stage)
