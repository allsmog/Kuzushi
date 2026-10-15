"""Owned inventory boundary and recovery fixture. Never execute source."""
import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "component").mkdir()
    (root / "component/source.rs").write_text("// Owned inventory source, never executed.\n")
    for args in [["init", "--quiet"], ["add", "component/source.rs"]]:
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    outside = evidence / "excluded-source"
    outside.mkdir()
    (outside / "source.rs").write_text("// Owned excluded fixture text, never executed.\n")
    (evidence / "source-before.sha256").write_text(digest(root / "component/source.rs"))
    (evidence / "excluded-before.sha256").write_text(digest(outside / "source.rs"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifacts(root):
    return [root / ".kuzushi/context-snapshot.json",
            root / ".kuzushi/v3/reports/suggested-shards.toml"]


def capture_prior(root, evidence):
    for index, path in enumerate(artifacts(root)):
        (evidence / f"prior-{index}.bin").write_bytes(path.read_bytes())
    previous = {str(path.relative_to(root)): digest(path) for path in (root / ".kuzushi/v3/runs").glob("*/result.json")}
    (evidence / "prior-results.json").write_text(json.dumps(previous))


def redirect(root, evidence):
    (root / "component").rename(root / "original-component")
    (root / "component").symlink_to(evidence / "excluded-source", target_is_directory=True)


def restore(root):
    assert (root / "component").is_symlink()
    (root / "component").unlink()
    (root / "original-component").rename(root / "component")


def damage_index(root, evidence):
    index = root / ".git/index"
    (evidence / "prior-index.bin").write_bytes(index.read_bytes())
    index.write_bytes(b"Owned invalid index fixture. No source execution.\n")


def restore_index(root, evidence):
    (root / ".git/index").write_bytes((evidence / "prior-index.bin").read_bytes())


def verify(root, evidence, stage):
    if stage == "blocked":
        for index, path in enumerate(artifacts(root)):
            assert path.read_bytes() == (evidence / f"prior-{index}.bin").read_bytes()
    original = root / ("original-component" if (root / "component").is_symlink() else "component")
    assert digest(original / "source.rs") == (evidence / "source-before.sha256").read_text()
    assert digest(evidence / "excluded-source/source.rs") == (evidence / "excluded-before.sha256").read_text()
    results = [(path, json.loads(path.read_text()))
               for path in sorted((root / ".kuzushi/v3/runs").glob("*/result.json"))]
    partial = stage.startswith("partial")
    status = "partial" if partial else "failed"
    failed = [(path, value) for path, value in results if value.get("status") == status]
    assert len(failed) == 2, [(str(path), value.get("status")) for path, value in results]
    failed_hashes = {path.parent.name: digest(path) for path, _ in failed}
    saved = evidence / ("partial-before.json" if partial else "failed-before.json")
    if stage in ["blocked", "partial"]:
        saved.write_text(json.dumps(failed_hashes))
    else:
        assert failed_hashes == json.loads(saved.read_text())
    for path, expected in json.loads((evidence / "prior-results.json").read_text()).items():
        assert digest(root / path) == expected
    if stage in ["recovered", "restarted", "partial-recovered", "partial-restarted"]:
        completed_context = [value for _, value in results
                             if value.get("status") == "completed" and value.get("data", {}).get("snapshot")]
        assert len(completed_context) == 2, "Explicit recovery must produce a second completed context receipt"
    (evidence / "failed-replay.txt").write_text("replay " + failed[-1][0].parent.name)
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts", "finding_observations", "review_decisions"]:
            if table in tables:
                assert db.execute("select count(*) from " + table).fetchone()[0] == 0, table
    (evidence / f"{stage}-check.json").write_text(json.dumps({"retainedOutcome": status, "retainedReceipts": 2,
        "providerCalls": 0, "sourceExecuted": False, "sourceBytesUnchanged": True,
        "priorArtifactsPreserved": stage == "blocked"}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence)
    elif stage == "capture":
        capture_prior(root, evidence)
    elif stage == "redirect":
        redirect(root, evidence)
    elif stage == "restore":
        restore(root)
    elif stage == "damage-index":
        damage_index(root, evidence)
    elif stage == "restore-index":
        restore_index(root, evidence)
    else:
        verify(root, evidence, stage)
