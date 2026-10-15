"""Labeled reader history only. No discovery executor or provider is invoked."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from investigation_brief import native, save
from secret_settings import ledger


def queue_path(root):
    return root / ".kuzushi/v3/campaigns/batch-test/queue.json"


def occurrence(root, evidence):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "findings", "batch", "batch-test", "--json"], capture_output=True, text=True, timeout=35)
    (evidence / "occurrence.stdout.txt").write_text(result.stdout)
    (evidence / "occurrence.stderr.txt").write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def facts(root, evidence):
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
            for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]}
    return {"counts": counts, "sourceSha256": hashlib.sha256((root / "source.rs").read_bytes()).hexdigest(),
        "planSha256": hashlib.sha256((queue_path(root).parent / "plan.json").read_bytes()).hexdigest()}


def seed(root, evidence):
    assert root == evidence / "fixture-target" and (root / ".git").is_dir()
    for name in ["main.rs", "app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    binary = Path(os.environ["KUZUSHI_DEVEX_RETAINED_FIXTURE_TEST_BIN"]).resolve()
    name = "findings::application::batch_occurrence::tests::retained_attempts::native_retained_attempt_fixture"
    result = subprocess.run([str(binary), "--exact", name, "--ignored", "--nocapture"],
        env=dict(os.environ, KUZUSHI_RETAINED_FIXTURE_ROOT=str(root)), capture_output=True, text=True, timeout=40)
    (evidence / "fixture-seed.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0 and "1 passed" in result.stdout, result.stdout + result.stderr
    receipt = json.loads((root / ".kuzushi/reader-fixture.json").read_text())
    assert receipt["synthetic"] and not receipt["executorsInvoked"]
    save(evidence, "fixture-executable", {"sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "receipt": receipt})
    save(evidence, "before", facts(root, evidence))
    verify(root, evidence)


def legacy(root, evidence):
    path = queue_path(root)
    original = evidence / "queue-before-legacy.json"
    assert not original.exists()
    original.write_bytes(path.read_bytes())
    queue = json.loads(path.read_text())
    for job in queue["jobs"].values():
        job.pop("dispatches", None)
    path.write_text(json.dumps(queue))
    status = native(root, evidence, "legacy-status", "campaign:status", {"campaignId": "batch-test"})["data"]
    assert all(job["dispatches"] is None for job in status["jobs"])


def restore(root, evidence):
    queue_path(root).write_bytes((evidence / "queue-before-legacy.json").read_bytes())
    verify(root, evidence)


def verify(root, evidence):
    report = occurrence(root, evidence)
    assert (report["completed"], report["planned"], report["failed"]) == (3, 3, 0)
    by_title = {row["representativeTitle"]: row for row in report["rows"]}
    expected = {"canceled-only": 0, "latest-only": 1, "repeated": 2, "superseded-only": 0}
    assert {title: row["seen"] for title, row in by_title.items()} == {
        "Labeled " + name + " observation": seen for name, seen in expected.items()}
    assert by_title["Labeled canceled-only observation"]["runIds"] == ["run-trial-1-a1"]
    assert by_title["Labeled latest-only observation"]["runIds"] == ["run-trial-1-a2"]
    assert by_title["Labeled superseded-only observation"]["runIds"] == ["run-trial-3-a1"]
    status = native(root, evidence, "current-status", "campaign:status", {"campaignId": "batch-test"})["data"]
    assert [job["dispatches"] for job in status["jobs"]] == [2, 1, 2]
    assert all(job["attempts"] == 1 for job in status["jobs"])
    assert facts(root, evidence) == json.loads((evidence / "before.json").read_text())
    counts = facts(root, evidence)["counts"]
    assert counts["finding_observations"] == 6
    assert all(value == 0 for key, value in counts.items() if key != "finding_observations")
    save(evidence, "verified", {"facts": facts(root, evidence), "sourceExecuted": False, "providerRequests": 0,
        "syntheticReaderHistory": True, "recurrence": {"canceled-only": 0, "latest-only": 1, "repeated": 2, "superseded-only": 0}, "totalAttempts": [2, 1, 2]})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    {"seed": seed, "verify": verify, "legacy": legacy, "restore": restore}[sys.argv[3]](root, evidence)
