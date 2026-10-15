"""Plan source-bound Review against an existing owned revision, without models."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from live_investigation import CONTROL, FIXTURE, INVESTIGATION, MODEL, git, sources
from live_source_revision import BRANCH, check_owner_config, counts
from secret_settings import save

CAMPAIGN = "owned-sha-review-v2-20261010"


def native(root, evidence, name, value, success):
    env = dict(os.environ, HOME=str(FIXTURE / "home"))
    for key in ["NODE_OPTIONS", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE",
                "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
        env.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", "campaign:review-study", "--input", json.dumps(value)],
        env=env, capture_output=True, text=True, timeout=45)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    receipt = json.loads(result.stdout)
    save(evidence, name, receipt)
    assert (result.returncode == 0) == success, (name, result.stderr, receipt)
    return receipt


def prepare(root, evidence):
    assert root == FIXTURE / "target"
    before = json.loads((CONTROL / "source-before.json").read_text())
    assert git(root, "branch", "--show-current") == "main"
    assert git(root, "rev-parse", "HEAD") == before["sha"]
    assert sources(root) == before["files"] and not git(root, "status", "--porcelain=v1")
    check_owner_config(before)
    original = counts(root, evidence)
    assert original == {"investigation_call_reservations": 4,
        "investigation_work_attempts": 6, "finding_observations": 3, "review_decisions": 1}
    for queue in (root / ".kuzushi/v3/campaigns").glob("*/queue.json"):
        assert all(job["state"] != "running" for job in json.loads(queue.read_text())["jobs"].values())
    manifest = root / ".kuzushi/threat-models/manifest.json"
    config = FIXTURE / "home/.kuzushi/v3/config.toml"
    save(evidence, "before", {"source": before, "counts": original,
        "manifestSha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "configSha256": hashlib.sha256(config.read_bytes()).hexdigest()})
    git(root, "switch", BRANCH)
    current = git(root, "rev-parse", "HEAD")
    assert current != before["sha"] and not git(root, "status", "--porcelain=v1")
    assert sources(root)["public-example.env"] == before["files"]["public-example.env"]
    value = {"campaignId": CAMPAIGN, "investigationId": INVESTIGATION,
        "reviewInput": {"strategy": "standard", "retriage": True,
                        "prefilterThreshold": 0, "model": MODEL}}
    refused = native(root, evidence, "stale-context-refusal", value, False)
    assert "Accepted Map belongs to earlier source" in json.dumps(refused)
    assert not (root / ".kuzushi/v3/campaigns" / CAMPAIGN).exists()
    value["reviewInput"]["threatModelRef"] = None
    native(root, evidence, "explicit-context-omission", value, True)
    save(evidence, "changed", {"sha": current, "files": sources(root)})
    verify(root, evidence)


def verify(root, evidence):
    assert root == FIXTURE / "target"
    before = json.loads((evidence / "before.json").read_text())
    changed = json.loads((evidence / "changed.json").read_text())
    assert git(root, "branch", "--show-current") == BRANCH
    assert git(root, "rev-parse", "HEAD") == changed["sha"]
    assert sources(root) == changed["files"] and not git(root, "status", "--porcelain=v1")
    check_owner_config(before["source"])
    assert counts(root, evidence) == before["counts"]
    directory = root / ".kuzushi/v3/campaigns" / CAMPAIGN
    plan = json.loads((directory / "plan.json").read_text())
    assert plan["sourceIdentity"].startswith("git:" + changed["sha"] + ";tree:")
    assert plan["investigationId"] == INVESTIGATION and len(plan["jobs"]) == 1
    assert plan["jobs"][0]["input"]["threatModelRef"] is None
    assert plan["jobs"][0]["input"]["strategy"] == "standard"
    assert plan["model"] == MODEL and len(plan["findings"]) == 1
    assert not (directory / "queue.json").exists()
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest.get("activeModelId") is None
    assert hashlib.sha256((root / ".kuzushi/threat-models/manifest.json").read_bytes()).hexdigest() == before["manifestSha256"]
    assert hashlib.sha256((FIXTURE / "home/.kuzushi/v3/config.toml").read_bytes()).hexdigest() == before["configSha256"]
    save(evidence, "verified", {"originalSha": before["source"]["sha"],
        "plannedReviewSha": changed["sha"], "providerRequestsAdded": 0,
        "targetExecuted": False, "counts": before["counts"],
        "contextExplicitlyOmitted": True, "reviewLaunched": False})


def restore(root, evidence):
    assert root == FIXTURE / "target"
    git(root, "switch", "main")
    before = json.loads((evidence / "before.json").read_text())
    assert git(root, "rev-parse", "HEAD") == before["source"]["sha"]
    assert sources(root) == before["source"]["files"]
    assert not git(root, "status", "--porcelain=v1")
    assert counts(root, evidence) == before["counts"]
    check_owner_config(before["source"])
    save(evidence, "restored", {"sha": before["source"]["sha"],
        "branch": "main", "providerRequestsAdded": 0})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    evidence.mkdir(parents=True, exist_ok=True)
    {"prepare": prepare, "verify": verify, "restore": restore}[sys.argv[3]](root, evidence)
