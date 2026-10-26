"""Read one completed real-model lesson. Never starts provider or source work."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from secret_settings import ledger, save

MODEL = "openai-codex:gpt-6-luna"
CAMPAIGN = "live-owned-lesson-20261026"
FIXTURE = Path(__file__).resolve().parents[3] / "scripts/devex/artifacts/live-lesson-prepared-20261026"


def read(path):
    return json.loads(path.read_text())


def unchanged_source_and_context(root):
    before = read(FIXTURE / "control/before.json")
    revision = subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
                              capture_output=True, check=False)
    assert revision.returncode != 0, "This retained fixture has no committed source revision"
    files = {path.name for path in root.iterdir() if path.name not in [".git", ".kuzushi", ".gitignore"]}
    assert files == set(before["source"])
    for name, expected in before["source"].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected
    paths = [(FIXTURE / "home/.kuzushi/v3/config.toml", "configSha256"),
             (root / ".kuzushi/threat-models/manifest.json", "contextManifestSha256")]
    for path, key in paths:
        assert hashlib.sha256(path.read_bytes()).hexdigest() == before[key]
    assert before["sourceBytes"] == 32
    return before


def completed_lesson(root):
    campaign = root / ".kuzushi/v3/campaigns" / CAMPAIGN
    plan = read(campaign / "plan.json")
    jobs = read(campaign / "queue.json")["jobs"]
    assert len(plan["jobs"]) == plan["workers"] == len(jobs) == 1
    job = jobs["context-001"]
    assert job["state"] == "completed" and job["attempts"] == job["dispatches"] == 1
    run = root / ".kuzushi/v3/runs" / job["runId"]
    result, metadata = read(run / "result.json"), read(run / "run.json")
    assert result["status"] == "completed" and result["data"]["accepted"] is False
    lesson = result["data"]["lesson"]
    assert lesson["state"] == "draft" and lesson["revision"] == 1
    assert lesson["generation"]["model"] == MODEL
    assert lesson["generation"]["sourceCapture"] == "included"
    assert lesson["generation"]["inputBytes"] == 2572
    assert lesson["generation"]["synthesisRequests"] == 1
    assert len(metadata["llmCalls"]) == 1
    call = metadata["llmCalls"][0]
    assert call["model"] == MODEL and call["callAttempted"] and call["providerSpendUnresolved"]
    assert plan["jobs"][0]["input"]["thinkingLevel"] == "low"
    return lesson, result["data"]["lessonRef"]


def unchanged_accounting(root, evidence, lesson):
    with ledger(root, evidence) as db:
        calls = db.execute("select call_json,settled_at,observed_usd,cost_complete from investigation_call_reservations").fetchall()
        assert len(calls) == 1 and calls[0][1] is not None
        assert calls[0][2] is None and not calls[0][3]
        assert json.loads(calls[0][0])["work"] == "learning"
        assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 1
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 1
        assert db.execute("select decision_verdict,author from review_decisions").fetchall() == [("confirmed", "human")]
        records = db.execute("select json_extract(payload_json,'$.details') from audit_events where subject='finding-lesson-v1' order by seq").fetchall()
        assert len(records) == 1 and json.loads(records[0][0]) == lesson
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions").fetchone()[0])
        assert approval["limits"] == {"maxProviderCalls": 1, "protectedReviewCalls": 0}


def verify(root, evidence, stage):
    assert root == (FIXTURE / "target").resolve(), "Use only the retained owned lesson fixture"
    unchanged_source_and_context(root)
    lesson, reference = completed_lesson(root)
    unchanged_accounting(root, evidence, lesson)
    save(evidence, stage + "-check", {"model": MODEL, "reasoning": "low", "jobs": 1,
        "attempts": 1, "providerRequests": 1, "newProviderRequests": 0,
        "cumulativeLiveExperimentRequests": 17, "remainingApprovedLiveRequests": 0,
        "settledReservations": 1, "unresolvedReservations": 0,
        "capturedSourceBytes": 32, "evidenceTextBytes": 2572, "lessonRef": reference,
        "lessonState": "draft", "sourceAndActiveContextUnchanged": True,
        "sourceRevision": "unavailable; owned unversioned fixture",
        "sourceExecuted": False, "automaticAcceptance": False, "dollars": "unknown"})


if __name__ == "__main__":
    target, output, stage = sys.argv[1:]
    verify(Path(target).resolve(), Path(output).resolve(), stage)
