"""Owned two-SHA source scans and scripted relationships. No provider calls."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from context_comparison import run_tool
from owned_source_revisions import BASELINE, LATER, create, git
from secret_settings import ledger


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def execute(root, evidence, label, tool, value, run_id=None):
    return run_tool(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, label,
                    tool, value, run_id)["data"]


def observations(root, evidence, label, later=False):
    paths = [f"book/{index:03}.env" for index in range(61) if not later or index != 1]
    result = execute(root, evidence, label, "sast:scan", {
        "taskMode": "manual", "tasks": ["secret-scan"], "paths": paths,
        "triage": False, "verify": False, "autoPatch": False, "patch": False,
        "pocExecution": False, "dynamicAnalysis": False,
        "secretScanMaxEntries": 512, "secretScanMaxTotalBytes": 65536,
        "secretScanMaxFileBytes": 2048, "secretScanMaxFindings": 100}, label)
    assert len(result["coreFindings"]) == len(paths)
    rows = execute(root, evidence, label + "-findings", "findings:list", {"limit": 100})["findings"]
    assert len(rows) == 61
    with ledger(root, evidence) as db:
        raw = [json.loads(row[0]) for row in db.execute("select finding_json from finding_observations order by created_seq")]
    latest = {row["file_path"]: row for row in raw}
    assert len(latest) == len(rows)
    return list(latest.values())


def propose(root, evidence, label, ids):
    (root / ".kuzushi/relationship-seed.json").write_text(json.dumps(ids))
    environment = dict(os.environ, KUZUSHI_RELATIONSHIP_BOOK_FIXTURE_OUT=str(root))
    result = subprocess.run([os.environ["KUZUSHI_RELATIONSHIP_BOOK_TEST_BIN"], "--exact", "--ignored",
        "app::relationships::tests::pagination::prepare_native_relationship_book_fixture", "--nocapture"],
        env=environment, capture_output=True, text=True, timeout=30, check=True)
    (evidence / (label + "-preparation.log")).write_text(result.stdout + result.stderr)
    records = json.loads((root / ".kuzushi/relationship-proposals.json").read_text())
    assert len(records) == len(ids) - 1
    save(evidence, label + "-proposals", records)
    return records


def source(root):
    names = set(git(root, "ls-files", "-z").split("\0"))
    names.update(str(path.relative_to(root)) for path in (root / "book").iterdir() if path.is_file())
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in names if name and not name.startswith(".kuzushi/")}


def prepare(parent, evidence):
    root = parent / "owned"
    create(root)
    (root / "book").mkdir()
    for index in range(61):
        (root / f"book/{index:03}.env").write_text("# Owned public example. No active credential. Never executed.\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    rows = sorted(observations(root, evidence, "relationship-baseline"), key=lambda row: row["file_path"])
    (evidence / "open-center.txt").write_text("open " + rows[0]["fingerprint"])
    records = propose(root, evidence, "baseline", [row["id"] for row in rows])
    save(evidence, "baseline-findings", rows)
    save(evidence, "baseline-source", source(root))
    save(evidence, "primary", records[0])
    (evidence / "accept-note.txt").write_text("Reviewed only baseline pair 001. Grouping does not confirm a vulnerability.")
    (evidence / "old-unlink-note.txt").write_text("Unlink only baseline pair 001 after the source change.")
    (evidence / "fresh-accept-note.txt").write_text("Reviewed only the fresh pair at the later source revision.")
    (evidence / "fresh-unlink-note.txt").write_text("Unlink only the fresh pair. Keep both raw generations.")
    inspect(root, evidence, "initial")


def later(root, evidence):
    assert git(root, "rev-parse", "HEAD") == BASELINE
    git(root, "switch", "fixture-later")
    rows = observations(root, evidence, "relationship-later", later=True)
    originals = json.loads((evidence / "baseline-findings.json").read_text())
    latest = {row["file_path"]: row for row in rows}
    assert latest[originals[1]["file_path"]]["id"] == originals[1]["id"]
    assert all(latest[row["file_path"]]["id"] != row["id"] for row in originals if row != originals[1])
    propose(root, evidence, "later", [latest[originals[index]["file_path"]]["id"] for index in [0, 2]])
    (evidence / "open-center.txt").write_text("open " + latest[originals[0]["file_path"]]["fingerprint"])
    save(evidence, "later-source", source(root))
    assert source(root) != json.loads((evidence / "baseline-source.json").read_text())
    inspect(root, evidence, "later")


def inspect(root, evidence, stage):
    baseline = stage in ["initial", "accepted"]
    assert git(root, "rev-parse", "HEAD") == (BASELINE if baseline else LATER)
    assert source(root) == json.loads((evidence / ("baseline-source.json" if baseline else "later-source.json")).read_text())
    pages = [execute(root, evidence, stage + "-relationships-" + str(offset),
             "findings:relationships", {"offset": offset}) for offset in [0, 50]]
    records = [row for page in pages for row in page["rows"]]
    assert len(records) == (60 if baseline else 61)
    primary = json.loads((evidence / "primary.json").read_text())
    by_id = {record["id"]: record for record in records}
    old = by_id[primary["id"]]
    expected_old = ("proposed", 1) if stage == "initial" else (("accepted", 2) if stage in ["accepted", "later"] else ("removed", 3))
    assert (old["state"], old["revision"]) == expected_old, old
    assert (old["from"], old["to"]) == (primary["from"], primary["to"])
    if not baseline:
        fresh = json.loads((evidence / "later-proposals.json").read_text())[0]
        current = by_id[fresh["id"]]
        expected_fresh = ("accepted", 2) if stage == "fresh-accepted" else (("removed", 3) if stage in ["finished", "restarted"] else ("proposed", 1))
        assert (current["state"], current["revision"]) == expected_fresh
        assert fresh["from"]["findingId"] != primary["from"]["findingId"]
    groups = execute(root, evidence, stage + "-groups", "findings:groups", {})
    assert groups["totalFindings"] == 61
    assert groups["totalGroups"] == (60 if stage in ["accepted", "fresh-accepted"] else 61), groups
    if stage == "later":
        assert groups["diagnostics"]["inactiveDuplicateLinks"] == 1
    dbpath = root / ".kuzushi/v3/index.sqlite3"
    assert dbpath.is_file()
    with ledger(root, evidence) as db:
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == (61 if baseline else 121)
        for name in ["review_decisions", "rekey_edges"]:
            assert db.execute("select count(*) from " + name).fetchone()[0] == 0
        snapshots = {row[0] for row in db.execute("select distinct git_commit from target_snapshots")}
        assert BASELINE in snapshots
        if not baseline:
            assert LATER in snapshots
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        if "investigation_call_reservations" in tables:
            assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 0
    save(evidence, stage + "-check", {"relationships": len(records), "rawObservations": 61 if baseline else 121,
        "identities": 61, "groups": groups["totalGroups"], "primaryState": expected_old[0],
        "primaryRevision": expected_old[1], "sourceSha": BASELINE if baseline else LATER,
        "findingDecisions": 0, "rekeys": 0, "providerRequests": 0, "sourceExecuted": False,
        "groupingDoesNotInferFixed": True, "localSourceScans": 1 if baseline else 2,
        "laterOmittedPath": None if baseline else "book/001.env", "publicExampleCredentialOnly": True})


def narrow(evidence):
    primary = json.loads((evidence / "primary.json").read_text())
    captures = sorted(evidence.glob("*-saved-details-*-40x12.txt"))
    assert len(captures) == 5
    body = "".join("".join(p.read_text().splitlines()[:6]) for p in captures)
    for endpoint in [primary["from"], primary["to"]]:
        assert str(endpoint["findingId"]) in body, "narrow paging skipped a recorded endpoint"
    assert "Recorded runs:" in body and "relationship-baseline" in body
    save(evidence, "narrow-check", {"captures":len(captures),"bothRecordedIdsReachable":True,"recordedRunsReachable":True})


if __name__ == "__main__":
    parent, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "prepare":
        prepare(parent, evidence)
    elif stage == "narrow":
        narrow(evidence)
    elif stage == "later":
        later(parent / "owned", evidence)
    else:
        inspect(parent / "owned", evidence, stage)
