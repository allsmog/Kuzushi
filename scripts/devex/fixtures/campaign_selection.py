"""Unstarted local history fixtures for stable investigation selection."""
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def plan_path(root, campaign):
    return root / ".kuzushi/v3/campaigns" / campaign / "plan.json"


def add_campaign(root, campaign, prefix):
    jobs = [{"jobId": prefix + "-" + str(index),
             "tool": "sast:scan", "input": {"tasks": ["secret-scan"]}}
            for index in [1, 2]]
    path = plan_path(root, campaign)
    write_json(path, {"campaignId": campaign, "tool": "sast:scan", "createdAtMs": 1, "jobs": jobs})
    write_json(path.with_name("queue.json"), {"jobs": {
        job["jobId"]: {"state": "planned", "attempts": 0, "dispatches": 0} for job in jobs}})


def verify(root, evidence):
    before = json.loads((evidence / "before.json").read_text())
    assert hashlib.sha256((root / "source.txt").read_bytes()).hexdigest() == before["sourceSha256"]
    for path in (root / ".kuzushi/v3/campaigns").glob("*/queue.json"):
        queue = json.loads(path.read_text())["jobs"]
        assert all(row == {"state": "planned", "attempts": 0, "dispatches": 0} for row in queue.values())
    index = root / ".kuzushi/v3/index.sqlite3"
    if index.exists():
        with sqlite3.connect(index.as_uri() + "?mode=ro", uri=True) as connection:
            tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
            for table in ["investigation_work_attempts", "investigation_call_reservations"]:
                if table in tables:
                    assert connection.execute("select count(*) from " + table).fetchone()[0] == 0
    write_json(evidence / "inspection-check.json", {"sourceUnchanged": True, "executedJobs": 0,
        "providerRequests": 0, "fixture": "labeled unapproved history, no source execution"})


def verify_paging(evidence):
    starts = []
    for label in ["paged-before-refresh", "paged-after-refresh"]:
        text = next(evidence.glob("*-" + label + ".txt")).read_text()
        match = re.search(r"rows (\d+)-", text)
        assert match, text
        starts.append(int(match.group(1)))
    assert starts[0] == starts[1] and starts[0] > 1, starts
    write_json(evidence / "paging-check.json", {"firstRows": starts, "preservedNonzeroPosition": True})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    action = sys.argv[3]
    if action == "seed":
        assert root == evidence / "fixture-target"
        (root / "source.txt").write_text("Labeled inert source. Never executed.\n")
        add_campaign(root, "held", "held")
        write_json(evidence / "before.json", {"sourceSha256": hashlib.sha256((root / "source.txt").read_bytes()).hexdigest()})
    elif action == "insert":
        add_campaign(root, "aaa", "other")
    elif action == "reorder":
        path = plan_path(root, "held")
        value = json.loads(path.read_text())
        value["jobs"].reverse()
        write_json(path, value)
    elif action == "remove":
        path = plan_path(root, "held")
        (evidence / "removed-plan.json").write_bytes(path.read_bytes())
        path.unlink()
    elif action == "paging":
        verify_paging(evidence)
    else:
        verify(root, evidence)
