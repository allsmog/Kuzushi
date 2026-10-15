"""Owned pending observation and real finite Review planning; no provider work."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from secret_settings import ledger


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def seed_pending(root, evidence, home):
    assert home == (evidence / "home").resolve()
    env = dict(os.environ, HOME=str(home), KUZUSHI_REVIEW_STUDY_FIXTURE_OUT=str(root))
    result = subprocess.run([os.environ["KUZUSHI_REVIEW_TEST_BIN"], "--exact",
        "capabilities::campaign::review_study::tests::prepare_native_review_study_fixture", "--nocapture"],
        env=env, text=True, capture_output=True, timeout=45, check=True)
    (evidence / "preparation.log").write_text(result.stdout + result.stderr)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    save(evidence, "source-before", {"sha256":hashlib.sha256((root / "note.md").read_bytes()).hexdigest()})
    return env


def seed(root, evidence, home):
    env = seed_pending(root, evidence, home)
    value = {"campaignId":"owned-review", "investigationId":"owned-review",
        "reviewInput":{"strategy":"standard","prefilterThreshold":0,"threatModelRef":None}}
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root),
        "run", "campaign:review-study", "--input", json.dumps(value)], env=env,
        text=True, capture_output=True, timeout=35, check=True)
    draft = json.loads(result.stdout)
    save(evidence, "native-draft", draft)
    (evidence / "native-draft.stderr.txt").write_text(result.stderr)
    verify(root, evidence, "prepared")


def verify(root, evidence, stage):
    assert hashlib.sha256((root / "note.md").read_bytes()).hexdigest() == json.loads((evidence / "source-before.json").read_text())["sha256"]
    plan = json.loads((root / ".kuzushi/v3/campaigns/owned-review/plan.json").read_text())
    assert plan["kind"] == "review-study" and plan["workers"] == 1
    assert len(plan["jobs"]) == len(plan["findings"]) == 1
    assert plan["jobs"][0]["input"]["fingerprints"] == ["generation:" + str(plan["findings"][0]["id"])]
    assert plan["jobs"][0]["input"]["threatModelRef"] is None
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts", "review_decisions"]:
            assert table not in tables or db.execute("select count(*) from " + table).fetchone()[0] == 0
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 1
    assert not (root / ".kuzushi/v3/campaigns/owned-review/queue.json").exists()
    if stage in ["approved", "restarted"]:
        result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
            "run", "campaign:allowance", "--input", json.dumps({"investigationId":"owned-review"})],
            env=dict(os.environ, HOME=str(evidence / "home")), text=True, capture_output=True,
            timeout=30, check=True)
        status = json.loads(result.stdout)
        allowance = status["data"]["allowance"]
        assert allowance["revision"] == 1
        assert allowance["limits"] == {"maxProviderCalls":4,"protectedReviewCalls":2}
        assert allowance["committedCalls"] == allowance["unresolvedCalls"] == 0
        assert len(allowance["workPlan"]["jobs"]) == 1
        assert allowance["workPlan"]["jobs"][0]["tool"] == "triage:run"
        assert allowance["workPlan"]["jobs"][0]["maxAttempts"] == 1
        save(evidence, stage + "-allowance", status)
    save(evidence, stage + "-verified", {"syntheticObservation":True, "providerRequests":0,
        "sourceExecuted":False, "sourceUnchanged":True, "workAttempts":0, "decisions":0})


def verify_guided(root, evidence):
    assert hashlib.sha256((root / "note.md").read_bytes()).hexdigest() == json.loads((evidence / "source-before.json").read_text())["sha256"]
    paths = list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    assert len(paths) == 1
    plan = json.loads(paths[0].read_text())
    assert plan["kind"] == "review-study" and len(plan["jobs"]) == 1
    assert plan["jobs"][0]["input"]["concurrency"] == 1
    assert plan["jobs"][0]["input"]["strategy"] == "deep"
    assert plan["jobs"][0]["input"]["threatModelRef"] is None
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts", "review_decisions"]:
            assert table not in tables or db.execute("select count(*) from " + table).fetchone()[0] == 0
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 1
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    save(evidence, "guided-verified", {"providerRequests":0,"sourceExecuted":False,
        "sourceUnchanged":True,"pendingObservations":1,"deepStrategyPreserved":True,"plan":plan})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif sys.argv[3] == "pending":
        seed_pending(root, evidence, Path(sys.argv[4]).resolve())
    elif sys.argv[3] == "guided":
        verify_guided(root, evidence)
    else:
        verify(root, evidence, sys.argv[3])
