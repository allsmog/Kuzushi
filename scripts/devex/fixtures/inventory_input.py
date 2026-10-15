"""Owned inventory input/cancellation fixture. Never execute target source."""
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

FILE_COUNT = 16_000


def source_digest(root):
    digest = hashlib.sha256()
    files = sorted(root.glob("modules/*/src/*.rs"))
    assert len(files) == FILE_COUNT
    for path in files:
        digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    for module in range(160):
        directory = root / "modules" / f"part-{module:03}" / "src"
        directory.mkdir(parents=True)
        for index in range(100):
            (directory / f"file-{index:03}.rs").write_text("// Owned inert inventory source. Never executed.\n")
    for args in [["init", "--quiet", "--initial-branch=main"], ["add", "modules"]]:
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    (evidence / "source-before.sha256").write_text(source_digest(root))
    create_utilities(evidence)


def create_utilities(evidence):
    directory = evidence / "tool-bin"
    directory.mkdir()
    real_git = shutil.which("git")
    assert real_git
    proxy = """#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
evidence = Path(__file__).resolve().parent.parent
armed = evidence / 'hold-inventory'
if 'ls-files' in sys.argv[1:] and armed.exists():
    marker = evidence / ('held-' + str(os.getpid()) + '.json')
    marker.write_text(json.dumps({'pid':os.getpid(), 'parent':os.getppid(), 'args':sys.argv[1:]}))
    deadline = time.monotonic() + 35
    while armed.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
os.execv(REAL_GIT, [REAL_GIT, *sys.argv[1:]])
""".replace("REAL_GIT", repr(real_git))
    (directory / "git").write_text(proxy)
    (directory / "git").chmod(0o755)


def live_children(evidence):
    children = []
    for path in evidence.glob("held-*.json"):
        value = json.loads(path.read_text())
        try:
            os.kill(value["pid"], 0)
            children.append(value)
        except ProcessLookupError:
            pass
    return children


def runs(root):
    records = []
    for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
        value = json.loads(path.read_text())
        if value.get("tool") == "context:build":
            records.append((path, value))
    return records


def confirm_live(root, evidence, stage):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        children = live_children(evidence)
        active = [(path, value) for path, value in runs(root) if value["status"] == "running"]
        if children and active:
            (evidence / (stage + "-check.json")).write_text(json.dumps({
                "confirmedLiveGitChildren": children, "activeRunIds": [path.parent.name for path, _ in active]}, indent=2) + "\n")
            return
        time.sleep(0.05)
    raise AssertionError("No confirmed live Git child alongside an active context run")


def owned_pane(root):
    output = subprocess.check_output(["tmux", "list-panes", "-a", "-F",
        "#{pane_id}\t#{pane_current_path}\t#{alternate_on}"], text=True)
    panes = [parts[0] for line in output.splitlines()
             if len(parts := line.split("\t")) == 3 and parts[2] == "1"
             and Path(parts[1]).resolve() == root]
    assert len(panes) == 1, "Owned target must identify exactly one live TUI pane"
    return panes[0]


def input_probe(root, evidence, text):
    confirm_live(root, evidence, "live-" + text)
    pane = owned_pane(root)
    started = time.monotonic_ns()
    subprocess.run(["tmux", "send-keys", "-t", pane, "-l", "--", text], check=True)
    while time.monotonic_ns() - started < 2_000_000_000:
        screen = subprocess.check_output(["tmux", "capture-pane", "-p", "-t", pane], text=True)
        elapsed_ms = (time.monotonic_ns() - started) / 1_000_000
        if text in screen:
            assert elapsed_ms <= 300, f"Observed echo took {elapsed_ms:.2f} ms"
            assert live_children(evidence), "Git wait ended before input observation"
            (evidence / (text + "-timing.json")).write_text(json.dumps({
                "elapsedMs": elapsed_ms, "budgetMs": 300, "pane": pane,
                "clock": "monotonic", "endPoint": "after pane capture returns",
                "gitChildConfirmedLiveBeforeAndAfter": True}, indent=2) + "\n")
            return
        time.sleep(0.01)
    raise AssertionError("Input echo never appeared in the owned pane")


def release_after_wait(root, evidence):
    confirm_live(root, evidence, "live-rebuild")
    started = time.monotonic()
    time.sleep(2)
    assert live_children(evidence), "Rebuild Git child stopped before the controlled wait ended"
    (evidence / "hold-inventory").unlink()
    (evidence / "rebuild-wait.json").write_text(json.dumps({
        "heldSeconds": time.monotonic() - started, "gitChildLiveAtRelease": True}, indent=2) + "\n")


def verify_completion(root, evidence):
    screen = subprocess.check_output(["tmux", "capture-pane", "-p", "-t", owned_pane(root)], text=True)
    assert "view:logs" in screen and "kz> rebuild-draft" in screen
    durations = [int(value) for value in re.findall(r"context:build finished in (\d+)s", screen)]
    assert durations and durations[-1] >= 2, durations
    assert "Ctrl+C request abort" not in screen
    (evidence / "completion-check.json").write_text(json.dumps({
        "visibleSeconds": durations, "draftPreserved": True, "viewPreserved": "logs",
        "idlePromptObserved": True}, indent=2) + "\n")


def verify(root, evidence, stage):
    assert source_digest(root) == (evidence / "source-before.sha256").read_text()
    expected = 2 if stage == "canceled" else 3
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        records = runs(root)
        if len(records) == expected and all(value["status"] != "running" for _, value in records):
            break
        time.sleep(0.05)
    assert len(records) == expected, [(path.parent.name, value["status"]) for path, value in records]
    assert all(value["status"] in ["completed", "canceled"] for _, value in records)
    canceled = [(path, value) for path, value in records if value["status"] == "canceled"]
    assert len(canceled) == 1
    assert not live_children(evidence), "Canceled Git child remains live"
    (evidence / "canceled-replay.txt").write_text("replay " + canceled[0][0].parent.name)
    canceled_result = canceled[0][0].parent / "result.json"
    digest = hashlib.sha256(canceled_result.read_bytes()).hexdigest()
    if stage == "canceled":
        (evidence / "canceled-before.sha256").write_text(digest)
        assert (root / ".kuzushi/context-snapshot.json").read_bytes() == (evidence / "prior-context.bin").read_bytes()
    else:
        assert digest == (evidence / "canceled-before.sha256").read_text()
        snapshot = json.loads((root / ".kuzushi/context-snapshot.json").read_text())
        assert snapshot["filesIndexed"] == FILE_COUNT
        assert snapshot["fileIndex"]["enumeration"] == "git-index"
        assert len(snapshot["filesSample"]) == 200
    no_billable_or_discovery_work(root)
    (evidence / (stage + "-check.json")).write_text(json.dumps({
        "sourceFiles": FILE_COUNT, "sourceBytesUnchanged": True, "canceledReceipts": 1,
        "contextRuns": expected, "providerRequests": 0, "sourceExecuted": False,
        "canceledGitChildrenStopped": True}, indent=2) + "\n")


def no_billable_or_discovery_work(root):
    path = root / ".kuzushi/v3/index.sqlite3"
    if not path.exists():
        return
    with sqlite3.connect(path.as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts", "finding_observations", "review_decisions"]:
            if table in tables:
                assert db.execute("select count(*) from " + table).fetchone()[0] == 0, table


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence)
    elif stage == "arm":
        (evidence / "hold-inventory").write_text("Owned bounded Git wait fixture")
        (evidence / "prior-context.bin").write_bytes((root / ".kuzushi/context-snapshot.json").read_bytes())
    elif stage == "release":
        (evidence / "hold-inventory").unlink()
    elif stage == "release-after-wait":
        release_after_wait(root, evidence)
    elif stage == "completion":
        verify_completion(root, evidence)
    elif stage.startswith("live-"):
        confirm_live(root, evidence, stage)
    elif stage.startswith("probe-"):
        input_probe(root, evidence, stage.removeprefix("probe-"))
    else:
        verify(root, evidence, stage)
