"""Owned historical Git inspection; cancel its controlled adapter, never target code."""
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import source_baselines as base


def save(evidence, name, value):
    base.save(evidence, name, value)


def records(root):
    return [list(row) for row in base.records(root)]


def prepare(root, evidence, home):
    assert root.name == "fixture-target" and root.parent == evidence
    base.prepare(root, evidence, home)
    base.git(root, "-c", "user.name=Owned fixture", "-c", "user.email=fixture@example.test",
             "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-m", "Owned metadata revision")
    save(evidence, "before-cancel", {"rows":records(root), "sha":base.git(root, "rev-parse", "HEAD"),
        "source":{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ["hello.txt", ".gitignore"]}})
    folder = evidence / "git-bin"
    folder.mkdir()
    shim = folder / "git"
    shim.write_text('''#!/usr/bin/python3
import json,os,sys,time
from pathlib import Path
control=Path(__file__).resolve().parent.parent
args=sys.argv[1:]
coverage_diff=all(value in args for value in ["diff","--no-ext-diff","--no-textconv","--name-only","-z","core.fsmonitor=false"])
if coverage_diff:
    record={"pid":os.getpid(),"startedNs":time.time_ns(),"args":args}
    with (control/"git-seen.jsonl").open("a") as stream:stream.write(json.dumps(record)+"\\n")
    if (control/"hold-diff").exists():
        (control/"git-held.json").write_text(json.dumps(record))
        time.sleep(60)
os.execv("/usr/bin/git", ["/usr/bin/git",*sys.argv[1:]])
''')
    shim.chmod(0o755)


def arm(evidence):
    seen = evidence / "git-seen.jsonl"
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if seen.exists():
            rows = [json.loads(line) for line in seen.read_text().splitlines()]
            if rows and all(not active(row["pid"]) for row in rows):
                save(evidence, "warmup-git", rows)
                (evidence / "hold-diff").touch()
                return
        time.sleep(0.02)
    raise AssertionError("Initial historical recommendation read did not settle before arming")


def active(pid):
    result = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "stat="], capture_output=True, text=True)
    return result.returncode == 0 and not result.stdout.strip().startswith("Z")


def blocked(evidence):
    marker = evidence / "git-held.json"
    deadline = time.monotonic() + 8
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert marker.exists(), "The real sweep never reached the controlled Git diff"
    assert active(json.loads(marker.read_text())["pid"])


def unchanged(root, evidence):
    before = base.load(evidence, "before-cancel")
    assert base.git(root, "rev-parse", "HEAD") == before["sha"]
    for name, digest in before["source"].items():
        assert hashlib.sha256((root/name).read_bytes()).hexdigest() == digest
    return before


def canceled(root, evidence):
    pid = base.load(evidence, "git-held")["pid"]
    start = base.load(evidence, "cancel-request")["requestedNs"]
    deadline = start + 3_000_000_000
    while active(pid) and time.time_ns() < deadline:
        time.sleep(0.02)
    elapsed = (time.time_ns() - start) / 1_000_000
    assert not active(pid) and elapsed <= 3000, f"Canceled Git adapter still active after {elapsed:.0f} ms"
    assert records(root) == unchanged(root, evidence)["rows"]
    (evidence / "hold-diff").unlink()
    save(evidence, "cancellation-proof", {"adapterExitedMs":elapsed, "historicalRowsUnchanged":True,
        "sourceExecuted":False, "providerRequests":0})


def completed(root, evidence):
    before = unchanged(root, evidence)
    rows = records(root)
    skips = [row for row in rows if row[2] == "sweep-skip"]
    assert len(rows) == len(before["rows"]) + 1 and len(skips) == 1
    assert skips[0][4] == before["sha"] and skips[0][0:2] == ["root", "scan"]
    save(evidence, "completed-proof", {"rows":rows, "skipCount":1, "providerRequests":0,
        "sourceExecuted":False, "sourceUnchanged":True})


if __name__ == "__main__":
    root, evidence, home = [Path(value).resolve() for value in sys.argv[1:4]]
    stage = sys.argv[4]
    if stage == "prepare": prepare(root, evidence, home)
    elif stage == "arm": arm(evidence)
    elif stage == "blocked": blocked(evidence)
    elif stage == "request": save(evidence, "cancel-request", {"requestedNs":time.time_ns()})
    elif stage == "canceled": canceled(root, evidence)
    else:
        assert stage == "completed"
        completed(root, evidence)
