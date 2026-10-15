"""Owned source-reader fixture. Product plans are prepared through visible controls."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from live_application_case import source_hashes
from secret_settings import ledger, save

MODEL = "openai-codex:gpt-5.5"
FIXTURE_TEST = "capabilities::campaign::review_study::tests::source_evidence::prepare_native_review_source_evidence_fixture"


def seed(root, evidence, home):
    assert not (evidence / "source-before.json").exists(), "Keep the existing fixture and receipts"
    env = dict(os.environ, HOME=str(home), KUZUSHI_REVIEW_SOURCE_FIXTURE_OUT=str(root))
    result = subprocess.run([env["KUZUSHI_REVIEW_TEST_BIN"], "--exact", FIXTURE_TEST,
        "--ignored", "--nocapture", "--test-threads=1"], env=env, text=True,
        capture_output=True, timeout=60)
    (evidence / "fixture-preparation.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0, "Inspect retained native fixture preparation log"
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = ' + json.dumps(MODEL) + '\n[runtime]\nthinking_level = "medium"\n')
    save(evidence, "source-before", source_hashes(root))
    save(evidence, "home-config-before", {"sha256": hashlib.sha256(config.read_bytes()).hexdigest()})


def verify(root, evidence, stage, home):
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    config = home / ".kuzushi/v3/config.toml"
    assert hashlib.sha256(config.read_bytes()).hexdigest() == json.loads((evidence / "home-config-before.json").read_text())["sha256"]
    plans = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    assert len(plans) == 1
    plan = plans[0]
    assert plan["kind"] == "review-study" and plan["workers"] == len(plan["jobs"]) == 1
    job = plan["jobs"][0]
    assert job["tool"] == "triage:run" and job["input"]["model"] == MODEL
    assert job["input"]["strategy"] == "standard" and job["input"]["sourceEvidence"] == "cited"
    assert job["input"]["sourceEvidenceRef"].startswith("review-evidence:")
    assert job["input"]["threatModelRef"] is None
    assert not (root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json").exists()
    results = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/runs").glob("*/result.json")]
    receipts = [r["data"] for r in results if isinstance(r.get("data"), dict) and r["data"].get("campaignId") == plan["campaignId"]]
    assert len(receipts) == 1
    source = receipts[0]["sourceEvidence"]
    assert source["schemaVersion"] == 1 and source["maxBytes"] == 32768
    text = (root / "note.md").read_text()
    assert source["includedBytes"] == len(text.encode())
    assert len(source["observations"]) == 1
    observation = source["observations"][0]
    assert observation["binding"] == "matching_recorded_snapshot" and observation["text"] == text
    with ledger(root, evidence) as db:
        tables = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts", "review_decisions", "investigation_allowance_revisions"]:
            assert table not in tables or db.execute("select count(*) from " + table).fetchone()[0] == 0, table
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 1
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    save(evidence, stage + "-verified", {"campaignId": plan["campaignId"], "frozenFiles": 1,
        "includedBytes": source["includedBytes"], "providerRequests": 0, "workAttempts": 0,
        "allowanceApprovals": 0, "sourceUnchanged": True, "sourceExecuted": False,
        "helperProductDispatches": 0, "syntheticObservation": True})


if __name__ == "__main__":
    root, evidence, home = [Path(p).resolve() for p in sys.argv[1:4]]
    if sys.argv[4] == "seed":
        seed(root, evidence, home)
    else:
        verify(root, evidence, sys.argv[4], home)
