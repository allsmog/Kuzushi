"""Labeled study reader history beyond a global page. No discovery or live model work."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from investigation_brief import native, save
from secret_settings import ledger


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def facts(root, evidence):
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {table: db.execute("select count(*) from " + table).fetchone()[0] if table in tables else 0
            for table in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]}
        observations = list(db.execute("select finding_json from finding_observations order by rowid"))
    campaign = root / ".kuzushi/v3/campaigns/batch-test"
    return {"counts": counts, "observationsSha256": hashlib.sha256(json.dumps(observations).encode()).hexdigest(),
        "files": {str(path.relative_to(root)): digest(path) for path in [root / "source.rs", campaign / "plan.json", campaign / "queue.json"]}}


def seed(root, evidence, home):
    assert root == evidence / "fixture-target" and (root / ".git").is_dir()
    for name in ["main.rs", "app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    binary = Path(os.environ["KUZUSHI_DEVEX_STUDY_PAGE_TEST_BIN"]).resolve()
    test = "findings::application::batch_occurrence::tests::page_membership::native_study_page_fixture"
    result = subprocess.run([str(binary), "--exact", test, "--ignored", "--nocapture"],
        env=dict(os.environ, KUZUSHI_STUDY_PAGE_FIXTURE_ROOT=str(root)), capture_output=True, text=True, timeout=90)
    (evidence / "fixture-seed.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0 and "1 passed" in result.stdout, result.stdout + result.stderr
    receipt = json.loads((root / ".kuzushi/study-page-fixture.json").read_text())
    assert receipt["synthetic"] and receipt["providerRequests"] == 0 and not receipt["sourceExecuted"]
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("# Owned reader fixture. No model or credentials.\n")
    save(evidence, "fixture-executable", {"path": str(binary), "sha256": digest(binary), "receipt": receipt})
    save(evidence, "before", facts(root, evidence))
    verify(root, evidence, "seeded")


def verify(root, evidence, stage):
    global_page = native(root, evidence, stage + "-global", "findings:list", {"limit": 500})["data"]
    assert global_page["page"]["total"] == 503 and len(global_page["findings"]) == 500
    assert all(row["severity"] == "critical" for row in global_page["findings"])
    first = native(root, evidence, stage + "-study", "findings:list", {"batchId": "batch-test", "limit": 2})["data"]
    assert first["batchId"] == "batch-test" and first["page"]["total"] == 3
    assert len(first["findings"]) == 2 and first["page"]["nextCursor"]
    second = native(root, evidence, stage + "-study-next", "findings:list",
        {"batch": "batch-test", "limit": 2, "cursor": first["page"]["nextCursor"]})["data"]
    assert second["page"]["total"] == 3 and len(second["findings"]) == 1
    assert second["page"]["nextCursor"] is None
    members = first["findings"] + second["findings"]
    assert {row["rule_id"] for row in members} == {"canceled-member", "completed-member", "superseded-member"}
    assert all(row["severity"] == "info" for row in members)
    tail = native(root, evidence, stage + "-global-tail", "findings:list",
        {"limit": 500, "cursor": global_page["page"]["nextCursor"]})["data"]
    assert {row["fingerprint"]: row["alias"] for row in members} == {
        row["fingerprint"]: row["alias"] for row in tail["findings"]}
    assert facts(root, evidence) == json.loads((evidence / "before.json").read_text())
    counts = facts(root, evidence)["counts"]
    assert counts["finding_observations"] == 504
    assert all(value == 0 for key, value in counts.items() if key != "finding_observations")
    save(evidence, stage + "-verified", {"syntheticReaderHistory": True, "globalFindings": 503, "studyFindings": 3,
        "outsideFindings": 500, "rawObservations": 504, "newProviderCalls": 0, "sourceExecuted": False,
        "newJobs": 0, "newDecisions": 0, "sourceAndHistoryUnchanged": True})


def hide_plan(root, evidence):
    assert facts(root, evidence) == json.loads((evidence / "before.json").read_text())
    plan = root / ".kuzushi/v3/campaigns/batch-test/plan.json"
    backup = evidence / "hidden-plan.json"
    assert not backup.exists()
    plan.rename(backup)


def restore_plan(root, evidence):
    (evidence / "hidden-plan.json").rename(root / ".kuzushi/v3/campaigns/batch-test/plan.json")
    assert facts(root, evidence) == json.loads((evidence / "before.json").read_text())


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif sys.argv[3] == "hide-plan":
        hide_plan(root, evidence)
    elif sys.argv[3] == "restore-plan":
        restore_plan(root, evidence)
    else:
        verify(root, evidence, sys.argv[3])
