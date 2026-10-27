"""Two real offline source scans with exact historical source export checks."""
import csv
import json
import os
import sys
from pathlib import Path

from context_comparison import run_tool
from owned_source_revisions import BASELINE, LATER, create, git
from relationship_book import propose
from secret_settings import ledger

PATHS = ["receipts/first.env", "receipts/second.env"]


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def execute(root, evidence, label, tool, value, run_id=None):
    return run_tool(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, label,
                    tool, value, run_id)["data"]


def raw_sources(root, evidence):
    with ledger(root, evidence) as db:
        return [{"finding": json.loads(row[0]), "snapshot": row[1], "blob": row[2],
                 "sha": row[3], "tree": row[4]} for row in db.execute(
            "select o.finding_json,o.snapshot_hash,o.blob_hash,s.git_commit,s.tree_hash "
            "from finding_observations o left join target_snapshots s "
            "on s.snapshot_hash=o.snapshot_hash order by o.created_seq")]


def scan(root, evidence, label, expected_sha):
    output = run_tool(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, label, "sast:scan", {
        "taskMode": "manual", "tasks": ["secret-scan"], "paths": PATHS,
        "triage": False, "verify": False, "autoPatch": False, "patch": False,
        "pocExecution": False, "dynamicAnalysis": False,
        "secretScanMaxEntries": 8, "secretScanMaxTotalBytes": 8192,
        "secretScanMaxFileBytes": 2048, "secretScanMaxFindings": 4}, label)
    assert output["status"] == "completed", output
    assert len(output["data"]["coreFindings"]) == 2
    rows = [row for row in raw_sources(root, evidence) if row["finding"]["scan_id"] == label]
    assert len(rows) == 2
    assert all(row["sha"] == expected_sha and row["blob"] and row["tree"] for row in rows)
    summary = json.loads((root / ".kuzushi/v3/runs" / label / "run.json").read_text())
    assert summary["targetGit"]["sha"] == expected_sha
    save(evidence, label + "-sources", rows)
    return sorted(rows, key=lambda row: row["finding"]["file_path"])


def prepare(parent, evidence):
    root = parent / "owned"
    create(root)
    (root / "receipts").mkdir()
    for index, name in enumerate(PATHS):
        (root / name).write_text(f"# Owned baseline public example {index}. Never executed.\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    rows = scan(root, evidence, "source-baseline", BASELINE)
    propose(root, evidence, "historical", [row["finding"]["id"] for row in rows])
    (evidence / "open-original.txt").write_text("open generation:" + str(rows[0]["finding"]["id"]))
    for index, row in enumerate(rows):
        (evidence / f"open-current-{index}.txt").write_text("open " + row["finding"]["fingerprint"])
    save(evidence, "source-baseline-bytes", {name: (root / name).read_text() for name in PATHS})
    check(root, evidence, "baseline")


def later(root, evidence):
    git(root, "switch", "fixture-later")
    for index, name in enumerate(PATHS):
        (root / name).write_text(f"# Owned later public example {index}. Never executed.\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    scan(root, evidence, "source-later", LATER)
    save(evidence, "source-later-bytes", {name: (root / name).read_text() for name in PATHS})
    check(root, evidence, "later")


def assert_sources(records):
    assert len(records) == 2
    for row in records:
        provenance = row["provenance"]
        source = provenance["observationSource"]
        assert source["schemaVersion"] == 1 and source["runId"] == "source-later"
        assert source["gitCommit"] == LATER and source["blobHash"] and source["treeHash"]
        assert provenance["runGit"]["sha"] == LATER
        refs = provenance["relationshipSources"]
        assert len(refs) == 2 and {ref["runId"] for ref in refs} == {"source-baseline"}
        assert {ref["gitCommit"] for ref in refs} == {BASELINE}
        endpoints = row["relationships"][0]
        assert {ref["generationId"] for ref in refs} == {
            endpoints["from"]["findingId"], endpoints["to"]["findingId"]}
        assert source["generationId"] not in {ref["generationId"] for ref in refs}
        assert row["lifecycleStatus"] not in ["fixed", "removed"]


def export(root, evidence):
    folder = root / ".kuzushi/reports"
    for format_name, name in [("json", "sources.json"), ("jsonl", "sources.jsonl"),
                              ("csv", "sources.csv"), ("sarif", "sources.sarif"),
                              ("markdown-bundle", "sources-bundle")]:
        execute(root, evidence, "export-" + format_name, "workspace:export-findings",
                {"format": format_name, "output": str(folder / name)})
    records = json.loads((folder / "sources.json").read_text())["findings"]
    assert_sources(records)
    lines = [json.loads(line) for line in (folder / "sources.jsonl").read_text().splitlines()]
    assert_sources(lines[1:])
    with (folder / "sources.csv").open(newline="") as stream:
        reader = csv.DictReader(stream)
        assert reader.fieldnames[-4:] == ["reasoning_assertion_count", "run_git", "observation_source", "relationship_sources"]
        rows = list(reader)
    assert len(rows) == 2
    for row in rows:
        assert json.loads(row["observation_source"])["gitCommit"] == LATER
        assert {ref["gitCommit"] for ref in json.loads(row["relationship_sources"])} == {BASELINE}
    results = json.loads((folder / "sources.sarif").read_text())["runs"][0]["results"]
    assert len(results) == 2
    for row in results:
        assert row["properties"]["kuzushiObservationSource"]["gitCommit"] == LATER
        assert {ref["gitCommit"] for ref in row["properties"]["kuzushiRelationshipSources"]} == {BASELINE}
    bundle = folder / "sources-bundle"
    entries = json.loads((bundle / "manifest.json").read_text())["findings"]
    assert len(entries) == 2
    for row in entries:
        assert row["observationSource"]["gitCommit"] == LATER
        assert {ref["gitCommit"] for ref in row["relationshipSources"]} == {BASELINE}
        text = (bundle / row["path"]).read_text()
        assert BASELINE in text and LATER in text
    save(evidence, "export-check", {"formats": 5, "findingsPerFormat": 2,
        "currentSha": LATER, "historicalRelationshipSha": BASELINE,
        "allCurrentFindingsReobserved": True, "inferredFixes": 0})


def check(root, evidence, stage):
    rows = raw_sources(root, evidence)
    expected_count = 2 if stage == "baseline" else 4
    assert len(rows) == expected_count
    assert all(row["sha"] in [BASELINE, LATER] and row["blob"] and row["tree"] for row in rows)
    if stage != "baseline":
        assert {row["sha"] for row in rows} == {BASELINE, LATER}
    with ledger(root, evidence) as db:
        names = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        decisions = db.execute("select count(*) from review_decisions").fetchone()[0]
        if "investigation_call_reservations" in names:
            assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 0
    assert decisions == (2 if stage in ["final", "restarted"] else 0)
    if stage in ["final", "restarted"]:
        exports = list((root / ".kuzushi/reports").glob("*.json"))
        assert any(path.name != "sources.json" and json.loads(path.read_text()).get("count") == 2
                   for path in exports), "TUI Report must produce its own real JSON export"
    assert not (evidence / "denied-fetch.jsonl").exists()
    save(evidence, stage + "-check", {"observations": expected_count, "decisions": decisions,
        "providerRequests": 0, "sourceExecuted": False, "sourceBindingKnown": True})


if __name__ == "__main__":
    parent, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    root = parent / "owned"
    if stage == "prepare":
        prepare(parent, evidence)
    elif stage == "later":
        later(root, evidence)
    elif stage == "remove":
        (root / PATHS[0]).unlink()
    elif stage == "restore":
        for name, text in json.loads((evidence / "source-later-bytes.json").read_text()).items():
            (root / name).write_text(text)
    elif stage == "narrow":
        captures = sorted(evidence.glob("*-retained-source-detail-*-40x12.txt"))
        assert len(captures) == 5
        text = "\n".join(path.read_text() for path in captures)
        assert "baseline" in text and ("run checkout" in text or "run Git" in text)
        assert "Owned later public" not in text
        save(evidence, "narrow-check", {"pages": 5, "historicalSourceReached": True, "runCheckoutLabelReached": True})
    elif stage == "export":
        export(root, evidence)
    else:
        check(root, evidence, stage)
