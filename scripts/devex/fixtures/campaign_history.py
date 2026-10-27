"""Owned unstarted history for bounded browsing and honest failure disclosure."""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def plan(base, identity, jobs, kind=None):
    document = {"campaignId": identity, "tool": "sast:scan", "jobs": jobs}
    if kind:
        document.update(kind=kind, requestedWorkers=1, effectiveWorkers=1)
    save(base / identity / "plan.json", document)


def verify(root, evidence, base):
    before = json.loads((evidence / "history-before.json").read_text())
    assert hashlib.sha256((root / "source.txt").read_bytes()).hexdigest() == before["sourceSha256"]
    assert hashlib.sha256((base / before["selectedId"] / "plan.json").read_bytes()).hexdigest() == before["heldSha256"]
    assert not list(base.glob("*/queue.json")), "Inspection created a queue"
    database = root / ".kuzushi/v3/index.sqlite3"
    counts = {}
    if database.exists():
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
            tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
            for table in ["investigation_work_attempts", "investigation_call_reservations", "finding_observations", "review_decisions"]:
                if table in tables:
                    counts[table] = connection.execute("select count(*) from " + table).fetchone()[0]
        assert all(value == 0 for value in counts.values()), counts
    save(evidence / "history-inspection-check.json", {"sourceUnchanged": True, "selectedPlanUnchanged": True,
         "queueCreated": False, "counts": counts, "liveProviderRequests": 0, "sourceExecuted": False,
         "fixture": "labeled synthetic unapproved history; inspection only"})


def choose_outside_view(root, evidence, base):
    command = [os.environ["KUZUSHI_NATIVE_BIN"], "run", "campaign:status", "--target", str(root)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (evidence / "headless-history.stdout.json").write_text(result.stdout)
    (evidence / "headless-history.stderr.txt").write_text(result.stderr)
    assert result.returncode == 4, result.stderr
    output = json.loads(result.stdout)
    assert output["status"] == "partial", output
    visible = {row["campaignId"] for row in output["data"]["campaigns"]}
    assert len(visible) == 100
    candidates = sorted(path.name for path in base.iterdir() if path.is_dir())
    selected = next(identity for identity in candidates if identity not in visible)
    jobs = [{"jobId": "held-" + str(index), "tool": "sast:scan", "input": {"tasks": ["secret-scan"]}} for index in [1, 2]]
    plan(base, selected, jobs, "scan-batch")
    (evidence / "history-exact-command.txt").write_text("campaign " + selected)
    save(evidence / "outside-view-proof.json", {"selectedId": selected, "initialVisibleIds": sorted(visible),
         "selectedOutsideInitialView": selected not in visible, "statusExitCode": result.returncode,
         "historyCoverage": output["data"]["historyCoverage"], "sourceExecuted": False, "liveProviderRequests": 0})
    return selected


def verify_paging(evidence):
    captures = [next(evidence.glob("*-history-read-page-" + str(index) + ".txt")) for index in [1, 2, 3]]
    text = "\n".join(path.read_text() for path in captures)
    assert "held-2" in text, text
    assert "0 total attempts" in " ".join(text.split()), text
    assert "Recorded cost: unknown" in text, text
    assert "r refresh" in text, text
    save(evidence / "history-paging-check.json", {"selectedJobReadable": True, "attemptsReadable": True,
         "unknownRecordedCostReadable": True, "refreshControlReadable": True,
         "captures": [path.name for path in captures], "keys": "three ordinary PageDown presses"})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    assert root == evidence / "fixture-target"
    base = root / ".kuzushi/v3/campaigns"
    action = sys.argv[3]
    if action == "seed":
        (root / "source.txt").write_text("Labeled inert greeting. Never executed.\n")
        for index in range(110):
            plan(base, "history-" + str(index).zfill(3), [])
        plan(base, "held", [{"jobId": "held-1", "tool": "sast:scan", "input": {"tasks": ["secret-scan"]}},
                            {"jobId": "held-2", "tool": "sast:scan", "input": {"tasks": ["secret-scan"]}}], "scan-batch")
        selected = choose_outside_view(root, evidence, base)
        save(evidence / "history-before.json", {"sourceSha256": hashlib.sha256((root / "source.txt").read_bytes()).hexdigest(),
             "heldSha256": hashlib.sha256((base / selected / "plan.json").read_bytes()).hexdigest(),
             "selectedId": selected, "declaredUnstartedPlans": 111})
    elif action == "damage":
        selected = json.loads((evidence / "history-before.json").read_text())["selectedId"]
        for path in base.iterdir():
            assert path.is_dir() and not path.is_symlink()
            if path.name != selected:
                assert path.name.startswith("history-") or path.name == "held"
                shutil.rmtree(path)
        broken = base / "broken/plan.json"
        broken.parent.mkdir(parents=True, exist_ok=True)
        broken.write_text("{")
        outside = evidence / "owned-external-history"
        plan(outside, "linked", [])
        (base / "linked").symlink_to(outside / "linked", target_is_directory=True)
    elif action == "paging":
        verify_paging(evidence)
    elif action == "block":
        verify(root, evidence, base)
        base.rename(evidence / "preserved-history")
        base.write_text("Owned regular file blocks this fixture's history directory.\n")
    elif action == "restore":
        assert base.is_file() and not base.is_symlink()
        base.unlink()
        (evidence / "preserved-history").rename(base)
    else:
        verify(root, evidence, base)
