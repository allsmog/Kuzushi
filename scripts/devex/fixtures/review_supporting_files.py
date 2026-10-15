"""Inert owned supporting-code fixture. Product input is chosen in the TUI."""
import hashlib
import json
import sys
from pathlib import Path

import review_source_evidence as source_fixture
from live_application_case import source_hashes
from secret_settings import ledger, save


def seed(root, evidence, home):
    source_fixture.FIXTURE_TEST = "capabilities::campaign::review_study::tests::source_evidence::prepare_native_review_supporting_files_fixture"
    source_fixture.seed(root, evidence, home)


def verify(root, evidence, home, stage):
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    config = home / ".kuzushi/v3/config.toml"
    assert hashlib.sha256(config.read_bytes()).hexdigest() == json.loads((evidence / "home-config-before.json").read_text())["sha256"]
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    assert len(plans) == 1
    plan = plans[0]
    assert plan["kind"] == "review-study" and plan["workers"] == len(plan["jobs"]) == 1
    job = plan["jobs"][0]
    assert job["tool"] == "triage:run" and job["input"]["model"] == source_fixture.MODEL
    assert job["input"]["sourceEvidenceFiles"] == ["service.txt", "store.txt"]
    assert job["input"]["sourceEvidence"] == "cited" and job["input"]["strategy"] == "standard"
    assert job["input"]["threatModelRef"] is None
    assert not (root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json").exists()
    results = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/runs").glob("*/result.json")]
    receipts = [result["data"] for result in results if isinstance(result.get("data"), dict) and result["data"].get("campaignId") == plan["campaignId"]]
    assert len(receipts) == 1
    source = receipts[0]["sourceEvidence"]
    assert source["schemaVersion"] == 2 and source["maxBytes"] == 32768
    observation, = source["observations"]
    assert observation["binding"] == "matching_recorded_snapshot"
    assert observation["text"] == (root / "note.md").read_text()
    assert [file["file"]["path"] for file in observation["supportingFiles"]] == ["service.txt", "store.txt"]
    total = len(observation["text"].encode())
    for file in observation["supportingFiles"]:
        assert file["file"]["state"] == "captured"
        assert file["text"] == (root / file["file"]["path"]).read_text()
        total += len(file["text"].encode())
    assert source["includedBytes"] == total
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts", "review_decisions", "investigation_allowance_revisions"]:
            assert table not in tables or db.execute("select count(*) from " + table).fetchone()[0] == 0, table
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 1
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    save(evidence, stage + "-verified", {"campaignId": plan["campaignId"], "supportingFiles": 2,
        "includedBytes": total, "providerRequests": 0, "workAttempts": 0, "allowanceApprovals": 0,
        "sourceUnchanged": True, "sourceExecuted": False, "helperProductDispatches": 0,
        "syntheticObservation": True})


if __name__ == "__main__":
    root, evidence, home = [Path(path).resolve() for path in sys.argv[1:4]]
    if sys.argv[4] == "seed":
        seed(root, evidence, home)
    else:
        verify(root, evidence, home, sys.argv[4])
