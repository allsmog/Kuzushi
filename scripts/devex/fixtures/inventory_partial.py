"""Owned partial inventory fixture. No source, scanner or model execution."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from secret_settings import ledger


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seed(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "component").mkdir()
    (root / "component/source.rs").write_text("// Owned inventory source. Never executed.\n")
    (root / "owned.py").write_text("# Owned root inventory source. Never executed.\n")
    (root / "pipe.rs").write_text("// Owned inventory source. Never executed.\n")
    outside = evidence / "excluded-source"
    outside.mkdir()
    (outside / "source.rs").write_text("// Owned excluded marker. Never executed.\n")
    for args in [["init", "--quiet", "--initial-branch=main"], ["add", "component/source.rs", "owned.py", "pipe.rs"]]:
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    (evidence / "source-before.json").write_text(json.dumps({
        "owned": digest(root / "owned.py"), "component": digest(root / "component/source.rs"),
        "pipe": digest(root / "pipe.rs"), "excluded": digest(outside / "source.rs")}))


def results(root):
    rows = []
    for path in (root / ".kuzushi/v3/runs").glob("*/result.json"):
        record = json.loads((path.parent / "run.json").read_text())
        rows.append((path, record, json.loads(path.read_text())))
    return rows


def capture(root, evidence):
    previous = {str(path.relative_to(root)): digest(path) for path, _, _ in results(root)}
    assert any(record.get("tool") == "context:build" and value["status"] == "completed" for _, record, value in results(root))
    (evidence / "previous-results.json").write_text(json.dumps(previous))


def redirect(root, evidence):
    (root / "component").rename(root / "original-component")
    (root / "component").symlink_to(evidence / "excluded-source", target_is_directory=True)
    (root / "pipe.rs").rename(root / "original-pipe.rs")
    os.mkfifo(root / "pipe.rs")


def verify(root, evidence, stage):
    before = json.loads((evidence / "source-before.json").read_text())
    assert digest(root / "owned.py") == before["owned"]
    assert digest(root / "original-component/source.rs") == before["component"]
    assert digest(root / "original-pipe.rs") == before["pipe"]
    assert digest(evidence / "excluded-source/source.rs") == before["excluded"]
    for path, expected in json.loads((evidence / "previous-results.json").read_text()).items():
        assert digest(root / path) == expected
    partials = [(path, record, value) for path, record, value in results(root) if value["status"] == "partial"]
    assert {record["tool"] for _, record, _ in partials} == {"context:build", "pack:suggest-shards"}
    assert len(partials) == 2
    for _, record, value in partials:
        data = value["data"]
        inspection = data.get("inspection") or data["snapshot"]["repositoryInventory"]["inspection"]
        assert inspection["files"] == ["owned.py"]
        assert {row["path"] for row in inspection["omitted_paths"]} == {"component/source.rs", "pipe.rs"}
        assert "excluded marker" not in json.dumps(value)
        assert value["warnings"] and "unsafe" in value["summary" if record["tool"] == "context:build" else "output"]
    selected = next(path for path, record, _ in partials if record["tool"] == "context:build")
    (evidence / "partial-replay.txt").write_text("replay " + selected.parent.name)
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts", "finding_observations", "review_decisions"]:
            if table in tables:
                assert db.execute("select count(*) from " + table).fetchone()[0] == 0
    (evidence / (stage + "-check.json")).write_text(json.dumps({"partialReceipts": 2,
        "safeMembers": 1, "recordedOmissions": 2, "providerCalls": 0, "scannerCalls": 0,
        "sourceExecuted": False, "sourceBytesPreserved": True, "earlierReceiptsPreserved": True}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence)
    elif stage == "capture":
        capture(root, evidence)
    elif stage == "redirect":
        redirect(root, evidence)
    else:
        verify(root, evidence, stage)
