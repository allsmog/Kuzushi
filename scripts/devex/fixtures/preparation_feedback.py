"""An owned workspace refusal and explicit recovery, with no model or source execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def seed(root, evidence, home):
    assert root.name == "fixture-target" and root.parent == evidence
    assert {path.name for path in root.iterdir()} <= {".git", "app.py", "config.env"}
    assert (root / ".git").is_dir()
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "main.rs").write_text("// Owned inert source for workspace preflight. Never execute.\n")
    (root / ".gitignore").write_text(".kuzushi/\n")
    (evidence / "runtime-home.txt").write_text(str(home))
    save(evidence, "source-before", {"main.rs": hashlib.sha256((root / "main.rs").read_bytes()).hexdigest()})


def native_read(root, evidence, name):
    env = dict(os.environ, HOME=(evidence / "runtime-home.txt").read_text())
    for key in ["NODE_OPTIONS", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
        env.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", "pack:scopes", "--input", '{"operation":"latest"}'],
        env=env, capture_output=True, text=True, timeout=30)
    (evidence / (name + ".stdout")).write_text(result.stdout)
    (evidence / (name + ".stderr")).write_text(result.stderr)
    return result


def ledger_counts(root, evidence, name):
    path = root / ".kuzushi/v3/index.sqlite3"
    names = ["finding_observations", "review_decisions", "investigation_call_reservations",
        "investigation_allowance_revisions", "investigation_work_attempts"]
    if not path.exists():
        return dict.fromkeys(names)
    sidecars = [Path(str(path) + suffix) for suffix in ["-wal", "-journal"]]
    assert all(not item.exists() or item.stat().st_size == 0 for item in sidecars)
    contents = path.read_bytes()
    snapshot = evidence / (name + ".sqlite3")
    snapshot.write_bytes(contents)
    assert path.read_bytes() == contents
    assert all(not item.exists() or item.stat().st_size == 0 for item in sidecars)
    with sqlite3.connect(snapshot.as_uri() + "?mode=ro&immutable=1", uri=True) as copy:
        tables = {row[0] for row in copy.execute("select name from sqlite_master where type='table'")}
        return {table: copy.execute("select count(*) from " + table).fetchone()[0]
            if table in tables else None for table in names}


def verify(root, evidence, stage):
    before = json.loads((evidence / "source-before.json").read_text())
    assert hashlib.sha256((root / "main.rs").read_bytes()).hexdigest() == before["main.rs"]
    assert not (root / ".kuzushi/v3/campaigns").exists()
    if stage == "refused":
        result = native_read(root, evidence, "refused-headless")
        assert result.returncode == 2 and "scope.toml" in result.stderr
        capture = next(evidence.glob("*-workspace-refused.txt")).read_text()
        assert "Your draft is preserved" in " ".join(capture.replace("│", " ").split())
        assert "Enter / c build inventory" in capture
        assert "Working · Ctrl+C cancel" not in capture
    elif stage == "fix":
        (root / ".gitignore").write_text("# Workspace state manages its own ignore policy.\n")
        return
    else:
        result = native_read(root, evidence, stage + "-headless")
        assert result.returncode == 0, result.stderr
        review = json.loads(result.stdout)["data"]["review"]
        assert review is not None and review["reference"]["revision"] == 1
        assert review["record"]["acceptance"] is None
        assert review["record"]["draft"]["scopes"][0]["paths"] == ["."]
        assert review["coverage"]["enumerationComplete"] is True
        assert review["coverage"]["inventoryLimited"] is True
        assert review["coverage"]["enumeratedFiles"] == 2
        inventory = root / ".kuzushi/v3/scan-scopes/inventories" / (review["record"]["inventoryHash"] + ".json")
        receipt = json.loads(inventory.read_text())
        assert receipt.get("truncation") is None
        assert receipt["inspection"]["enumeration_complete"] is True
        assert receipt["inspection"]["truncated_files"] == []
        assert {item["path"] for item in receipt["inspection"]["omitted_paths"]} == {".git", ".kuzushi"}
    counts = ledger_counts(root, evidence, stage)
    assert all(value in [0, None] for value in counts.values()), counts
    save(evidence, stage + "-check", {"sourceFileUnchanged": True, "configurationChangedExplicitly": stage != "refused", "sourceExecuted": False,
        "providerRequests": 0, "ledgerCounts": counts})


if __name__ == "__main__":
    stage, target, output = sys.argv[1:4]
    root, evidence = Path(target).resolve(), Path(output).resolve()
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, stage)
