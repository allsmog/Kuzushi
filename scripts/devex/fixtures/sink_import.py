"""Owned catalog metadata fixture. No source execution or provider calls."""
import hashlib
import json
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

TOOL = "taint-iris-next:import-sinks"


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    source = root / "README.md"
    source.write_text("Owned inert metadata fixture. Source is never executed.\n")
    (evidence / "source.sha256").write_text(hashlib.sha256(source.read_bytes()).hexdigest())
    saved = root / ".kuzushi/taint-iris-next-catalog.json"
    saved.parent.mkdir(parents=True, exist_ok=True)
    saved.write_text("Owned malformed catalog. Preserve until explicitly replaced.")
    (evidence / "prior-catalog.bin").write_bytes(saved.read_bytes())
    inventory = evidence / "owned inventory.jsonl "
    inventory.write_text('{"callee":"OwnedAlpha","cwe":"CWE-20"}\ninvalid\n{}\n')
    for stage, options in [("merge", {}), ("replace", {"merge": False})]:
        value = {"sinksPath": str(inventory), **options}
        (evidence / (stage + "-command.txt")).write_text("run " + TOOL + " " + json.dumps(value))


def results(root, count):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        found = []
        for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
            value = json.loads(path.read_text())
            if value.get("tool") == TOOL:
                found.append((path.parent, value))
        if len(found) == count and all(value["status"] != "running" for _, value in found):
            return found
        time.sleep(0.05)
    raise AssertionError("Expected terminal import receipts were not observed")


def verify(root, evidence, stage):
    source = root / "README.md"
    assert hashlib.sha256(source.read_bytes()).hexdigest() == (evidence / "source.sha256").read_text()
    records = results(root, 1 if stage == "failed" else 2)
    failed = [(path, value) for path, value in records if value["status"] == "failed"]
    assert len(failed) == 1
    result = failed[0][0] / "result.json"
    digest = hashlib.sha256(result.read_bytes()).hexdigest()
    saved = root / ".kuzushi/taint-iris-next-catalog.json"
    if stage == "failed":
        assert saved.read_bytes() == (evidence / "prior-catalog.bin").read_bytes()
        (evidence / "failure.sha256").write_text(digest)
        (evidence / "failure-replay.txt").write_text("replay " + failed[0][0].name)
    else:
        assert digest == (evidence / "failure.sha256").read_text()
        partial = [(path, value) for path, value in records if value["status"] == "partial"]
        assert len(partial) == 1
        data = json.loads((partial[0][0] / "result.json").read_text())
        assert data["status"] == "partial" and data["data"]["skippedLines"] == 2
        assert data["data"]["importedRows"] == 1 and data["warnings"]
        stored = json.loads(saved.read_text())
        assert len(stored["catalog"]) == 1
        assert stored["catalog"][0]["sinkSignals"] == ["OwnedAlpha("]
        (evidence / "partial-replay.txt").write_text("replay " + partial[0][0].name)
    accounting = assert_no_investigation_work(root)
    (evidence / (stage + "-check.json")).write_text(json.dumps({
        "toolRuns": len(records), "sourceBytesUnchanged": True, "failedReceiptRetained": True,
        "providerRequests": 0, "sourceExecution": False, "findingsAndInvestigationWork": 0,
        "accountingTables": accounting}, indent=2) + "\n")


def assert_no_investigation_work(root):
    observed = {}
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
            count = db.execute("select count(*) from " + table).fetchone()[0] if table in tables else None
            assert count in [0, None]
            observed[table] = count
    for path in (root / ".kuzushi/v3/runs").glob("*/items.jsonl"):
        for line in path.read_text().splitlines():
            kind = json.loads(line)["item"]["type"]
            assert isinstance(kind, str)
            assert not kind.startswith("model_call"), "Import created a model call"
    for path in (root / ".kuzushi").glob("**/phase-attempts*.jsonl"):
        assert not path.read_text().strip(), "Metadata import created phase evidence"
    return observed


def scroll_to_warning(root, evidence):
    output = subprocess.check_output(["tmux", "list-panes", "-a", "-F",
        "#{pane_id}\t#{pane_current_path}\t#{alternate_on}"], text=True)
    panes = [parts[0] for line in output.splitlines()
             if len(parts := line.split("\t")) == 3 and parts[2] == "1"
             and Path(parts[1]).resolve() == root]
    assert len(panes) == 1
    for pages in range(100):
        screen = subprocess.check_output(["tmux", "capture-pane", "-p", "-t", panes[0]], text=True)
        if "Complete import" in screen:
            (evidence / "warning-paging.json").write_text(json.dumps({"pages": pages, "warningVisible": True}) + "\n")
            return
        subprocess.run(["tmux", "send-keys", "-t", panes[0], "NPage"], check=True)
        time.sleep(0.05)
    raise AssertionError("Warning was not reachable through the owned Replay pager")


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence)
    elif stage == "warning":
        scroll_to_warning(root, evidence)
    else:
        verify(root, evidence, stage)
