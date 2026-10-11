"""Owned source inventory and context slices, without scanner or model work."""
import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path


def sources(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [root / "root.rs", root / "nested/service.rs", root / "outside.py"]}


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "nested").mkdir()
    (root / "root.rs").write_text("// Owned context inventory fixture; never executed.\n")
    (root / "nested/service.rs").write_text("// Owned truncated source inspection fixture.\n" + "// source-only filler\n" * 15000)
    (root / "outside.py").write_text("# Owned untracked source; never executed.\n")
    for args in [["init", "--quiet"], ["add", "root.rs", "nested/service.rs"]]:
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    (evidence / "sources-before.json").write_text(json.dumps(sources(root), indent=2) + "\n")


def read(root):
    path = root / ".kuzushi/context-snapshot.json"
    return path, json.loads(path.read_text())


def no_work(root):
    path = root / ".kuzushi/v3/index.sqlite3"
    if not path.exists():
        return
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts", "finding_observations", "review_decisions"]:
            if table in tables:
                assert db.execute("select count(*) from " + table).fetchone()[0] == 0, table


def inspect(root, evidence, stage):
    path, snapshot = read(root)
    receipt = snapshot["repositoryInventory"]["inspection"]
    assert receipt["enumeration"] == snapshot["fileIndex"]["enumeration"] == "git-index"
    assert set(receipt["files"]) == {"root.rs", "nested/service.rs"}
    assert snapshot["filesIndexed"] == 2
    assert receipt["max_entries"] == 100000
    assert receipt["max_inspected_bytes"] == 536870912
    assert receipt["max_file_inspection_bytes"] == 262144
    assert receipt["truncated_files"] == ["nested/service.rs"]
    expected = 2 if stage in ["rebuilt", "recovered"] else 1
    assert len(snapshot["filesSample"]) == expected
    if expected == 1:
        assert snapshot["filesSample"] == ["root.rs"]
    assert "outside.py" not in snapshot["filesSample"]
    reference = evidence / "context-before.bin"
    if stage == "built":
        reference.write_bytes(path.read_bytes())
    elif stage in ["invalid", "stale"]:
        assert path.read_bytes() == reference.read_bytes(), "Prior snapshot changed without a valid rebuild"
    if stage == "rebuilt":
        (evidence / "context-rebuilt.bin").write_bytes(path.read_bytes())
    elif stage == "recovered":
        assert path.read_bytes() == (evidence / "context-rebuilt.bin").read_bytes()
    before = json.loads((evidence / "sources-before.json").read_text())
    if stage in ["stale", "rebuilt", "recovered"]:
        assert sources(root)["root.rs"] != before["root.rs"]
        assert sources(root)["nested/service.rs"] == before["nested/service.rs"]
        assert sources(root)["outside.py"] == before["outside.py"]
    else:
        assert sources(root) == before
    no_work(root)
    (evidence / (stage + "-check.json")).write_text(json.dumps({"enumeration":"git-index", "enumeratedFiles":2,
        "sampledFiles":expected, "truncatedContentFiles":1, "untrackedSourceExcluded":True,
        "providerRequests":0, "scannerJobs":0, "sourceExecuted":False,
        "onlyPlannedInertSourceEdit":stage in ["stale", "rebuilt", "recovered"]}, indent=2) + "\n")


def inspect_pages(root, evidence):
    captures = sorted(evidence.glob("*-context-page-*-40x12.txt"))
    assert len(captures) == 12, "Missing actual narrow page captures"
    body = []
    for capture in captures:
        lines = capture.read_text().splitlines()
        chrome = next(index for index, line in enumerate(lines) if line.startswith("⛭"))
        body.extend(lines[:chrome])
    text = " ".join(" ".join(body).split())
    for value in ["Enumeration: Git tracked files.", "Untracked source is outside this inventory.",
        "Sample: 1 of 2 enumerated files", "100000", "262196", "536870912", "262144",
        "Recorded omissions: 0 paths.", "Files inspected only in part: 1.",
        "Inventory: partial.", "Provenance and manifest checks have separate work.",
        "context build", "context status", "context regen repo", "context regen app-model"]:
        assert value in text, (value, text)
    assert sources(root) == json.loads((evidence / "sources-before.json").read_text())
    no_work(root)
    (evidence / "pages-check.json").write_text(json.dumps({"actualPages":len(captures),
        "completeReceiptThroughPageKeys":True, "sourceChanged":False}, indent=2) + "\n")


root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
if stage == "prepare":
    prepare(root, evidence)
elif stage == "drift":
    (root / "root.rs").write_text("// Owned planned source revision; never executed.\n")
elif stage == "pages":
    inspect_pages(root, evidence)
else:
    inspect(root, evidence, stage)
