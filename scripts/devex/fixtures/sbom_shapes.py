"""Owned dependency metadata failure, correction and retained-run checks."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source_hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["package.json", "packages/child/package.json", "README.md"]}


def child_document(broken):
    dependencies = ["owned-child"] if broken else {"owned-child": "file:../shared"}
    return json.dumps({"devDependencies": dependencies}) + "\n"


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "packages/child").mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({
        "name": "owned-shapes",
        "dependencies": {"owned-root": "^1.0"},
        "optionalDependencies": {"compat-owned": {"version": "~2.0"}},
        "scripts": {"postinstall": "touch must-not-execute"}}) + "\n")
    (root / "packages/child/package.json").write_text(child_document(False))
    (root / "README.md").write_text("Owned inert dependency metadata. No package installation.\n")
    save(evidence, "valid-source", source_hashes(root))


def edit(root, evidence, broken):
    expected = "valid-source" if broken else "broken-source"
    assert source_hashes(root) == json.loads((evidence / (expected + ".json")).read_text())
    (root / "packages/child/package.json").write_text(child_document(broken))
    save(evidence, "broken-source" if broken else "corrected-source", source_hashes(root))


def assert_no_investigation(root):
    index = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(index.as_uri() + "?mode=rw", uri=True) as db:
        db.execute("pragma query_only = on")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for name in ["finding_observations", "review_decisions", "investigation_call_reservations",
                     "investigation_work_attempts"]:
            if name in tables:
                assert db.execute("select count(*) from " + name).fetchone()[0] == 0, name
    for name in ["phase-attempts.jsonl", "phase-attempts.v2.jsonl"]:
        path = root / ".kuzushi/workflow" / name
        assert not path.exists() or not path.read_text().strip(), name
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    assert not (root / "must-not-execute").exists()


def inspect(root, evidence, stage):
    expected = "broken-source" if stage == "failed" else "valid-source"
    assert source_hashes(root) == json.loads((evidence / (expected + ".json")).read_text())
    assert_no_investigation(root)
    receipts = {path.parent.name: json.loads(path.read_text())
                for path in (root / ".kuzushi/v3/runs").glob("*/result.json")}
    failures = {key: row for key, row in receipts.items() if row.get("status") == "failed"}
    completed = {key: row for key, row in receipts.items() if row.get("status") == "completed"}
    assert len(completed) == (2 if stage in ["corrected", "restarted"] else 1), receipts
    assert len(failures) == (0 if stage == "initial" else 1), receipts
    for row in completed.values():
        assert_complete(row)
    for row in failures.values():
        assert_failed(evidence, row)
    if stage == "restarted":
        assert sorted(receipts) == json.loads((evidence / "corrected-check.json").read_text())["runs"]
    save(evidence, stage + "-check", {"runs": sorted(receipts), "completed": len(completed),
         "failed": len(failures), "sourceMatchesExpectedStage": True, "sourceExecuted": False,
         "providerRequests": 0, "findings": 0, "phaseAttempts": 0, "discoveryJobs": 0})


def assert_complete(row):
    data = row["data"]
    assert data["componentCount"] == 3, data
    assert {item["name"] for item in data["components"]} == {
        "owned-root", "compat-owned", "owned-child"}, data
    assert {item["version"] for item in data["components"]} == {"^1.0", "~2.0", "file:../shared"}
    assert {item["to"] for item in data["dependencies"]} == {
        "owned-root", "compat-owned", "owned-child"}, data
    assert data["inspection"]["capturedFiles"] == 2, data


def assert_failed(evidence, row):
    text = json.dumps(row)
    assert "packages/child/package.json" in text, row
    assert "devDependencies must be an object" in text, row
    assert "components" not in row["data"] and "dependencies" not in row["data"], row
    inspection = row["data"]["inspection"]
    assert inspection["capturedFiles"] == 2, inspection
    expected = json.loads((evidence / "broken-source.json").read_text())
    for item in inspection["inputs"]:
        assert item["sha256"] == "sha256:" + expected[item["path"]], item


def inspect_failure_pages(evidence):
    pages = sorted(evidence.glob("*-failure-page-*-40x12.txt"))
    assert len(pages) == 2, pages
    pages = sorted(evidence.glob("*-failed-40x12.txt")) + pages
    assert len(pages) == 3, pages
    body = "".join("".join(path.read_text().split()) for path in pages)
    for value in ["packages/child/package.json", "devDependencies must be an object",
                  "Check the reported file or limit", "run sbom-scan:scan", "options sbom-scan:scan"]:
        assert "".join(value.split()) in body, value
    for value in ["owned-root", "compat-owned", "owned-child"]:
        assert value not in body, value
    save(evidence, "failure-pages-check", {"pages": len(pages), "fullCauseAndRecoveryReachable": True,
         "stalePackageClaimsAbsent": True, "formalOperatorAcceptance": False})


if __name__ == "__main__":
    root, evidence = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    stage = sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence)
    elif stage in ["break", "correct"]:
        edit(root, evidence, stage == "break")
    elif stage == "failure-pages":
        inspect_failure_pages(evidence)
    else:
        inspect(root, evidence, stage)
