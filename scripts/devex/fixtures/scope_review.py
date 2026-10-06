"""Offline scope review fixture. No scanners, model requests, or study jobs."""
import json
import sqlite3
import sys
from pathlib import Path


def seed(root, evidence):
    assert root.name == "fixture-target", "Only the harness-owned fixture is supported"
    for name in ("app.py", "config.env"):
        (root / name).unlink(missing_ok=True)
    for name in ("auth", "server"):
        (root / name).mkdir(exist_ok=True)
    (root / "auth/login.rs").write_text("pub fn login() {}\n")
    (root / "server/router.rs").write_text("pub fn route() {}\n")
    (root / "README.md").write_text("Labeled repository scope fixture.\n")
    (evidence / "split-paths.txt").write_text("README.md\nserver")
    (evidence / "rename.txt").write_text("Authentication")


def latest(root):
    entries = [json.loads(line) for line in (root / ".kuzushi/v3/strategy-queue.jsonl").read_text().splitlines()]
    scopes = [entry for entry in entries if entry.get("scopeProposalRef")]
    assert len(scopes) == 1
    head = scopes[0]
    assert head.get("tool") is None and head.get("nextInput") is None
    reference = head["scopeProposalRef"]
    path = root / ".kuzushi/v3/scan-scopes/revisions" / (reference["recordHash"] + ".json")
    return reference, json.loads(path.read_text())


def verify(root, evidence, stage):
    reference, record = latest(root)
    expected = {"split": 2, "renamed": 3, "accepted": 4, "drift": 4, "restarted": 4}[stage]
    assert reference["revision"] == expected, reference
    scopes = record["draft"]["scopes"]
    assert len(scopes) == 2
    assert scopes[0]["paths"] == ["auth"]
    assert scopes[1]["paths"] == ["README.md", "server"]
    if stage != "split":
        assert scopes[0]["name"] == "Authentication"
    if stage in ("accepted", "drift", "restarted"):
        assert record["acceptance"]["inventoryLimitations"] is True
    else:
        assert record["acceptance"] is None
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json")), "Scope review cannot compile jobs"
    for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
        assert json.loads(path.read_text()).get("tool") == "pack:scopes", "Unexpected tool execution"
    db = root / ".kuzushi/v3/index.sqlite3"
    if db.is_file():
        with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as connection:
            tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
            for table in ("investigation_work_attempts", "investigation_call_reservations"):
                if table in tables:
                    assert connection.execute(f"select count(*) from {table}").fetchone()[0] == 0
    (evidence / f"scope-{stage}.json").write_text(json.dumps({
        "reference": reference, "source": record["source"], "scopes": scopes,
        "accepted": record["acceptance"] is not None, "scanJobsStarted": 0,
        "providerCalls": 0, "sourceDriftIntroduced": stage in ("drift", "restarted"),
    }, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence)
    elif stage == "change-source":
        (root / "README.md").write_text("Changed labeled repository scope fixture.\n")
    else:
        verify(root, evidence, stage)
