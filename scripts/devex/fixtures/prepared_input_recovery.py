"""Prepared input survives owned transport refusal and an owned shell crash."""
import hashlib
import json
import os
import shutil
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

import systems_deep as base
import taint_catalog as catalog
from secret_settings import ledger, save


def calls(evidence):
    path = evidence / "prepared-calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def seed(root, evidence, home):
    base.seed(root, evidence, home)
    shutil.copyfile(Path(__file__).with_name("prepared_input_provider.mjs"), evidence / "provider.mjs")
    (evidence / "transport-mode.txt").write_text("fail\n")
    catalog.command(evidence, "approval", "campaign:approve-allowance", {
        "investigationId": base.INVESTIGATION, "expectedRevision": 0, "model": catalog.MODEL,
        "maxProviderCalls": 3, "protectedReviewCalls": 1,
        "reason": "Two separately invoked intercepted requests, one refusal and one owned interruption. One Review call stays protected. No live provider, source execution, retries or follow-up work."})
    value = json.loads((evidence / "generate-command.txt").read_text().split(" ", 2)[2])
    for name in ["failure", "interruption"]:
        value["allowanceRef"]["workId"] = "prepared-" + name
        catalog.command(evidence, name, base.TOOL, value)


def wait_calls(evidence, count):
    for _ in range(100):
        rows = calls(evidence)
        if len(rows) == count:
            return rows
        time.sleep(0.1)
    raise AssertionError(("Expected bounded intercepted request", count, calls(evidence)))


def stopped(root, evidence, name, status, count):
    rows = wait_calls(evidence, count)
    assert all(row["inputPreparedBeforeFetch"] and row["rawRuntimePromptVerified"]
               and row["liveProviderRequests"] == row["tools"] == 0 for row in rows)
    run_id = rows[-1]["runId"]
    run = root / ".kuzushi/v3/runs" / run_id
    for _ in range(100):
        result = run / "result.json"
        if result.exists():
            output = json.loads(result.read_text())
            if output["status"] == status:
                break
        time.sleep(0.1)
    else:
        raise AssertionError(("Expected stopped result", run_id, status))
    retained = json.loads((run / "prepared-model-input.json").read_text())
    assert output["data"]["inputDocument"] == retained["data"]["inputDocument"]
    assert "Provider delivery is not established" in output["data"]["inputDocument"]["text"]
    assert "owned_input" in output["data"]["inputDocument"]["text"]
    (evidence / (name + "-replay-command.txt")).write_text("replay " + run_id)
    invariant(root, evidence, name, count)


def invariant(root, evidence, name, count):
    assert base.hashes(root) == json.loads((evidence / "source-before.json").read_text())
    baseline = json.loads((evidence / "baseline.json").read_text())
    assert hashlib.sha256(Path(baseline["path"]).read_bytes()).hexdigest() == baseline["sha256"]
    assert not (root / ".kuzushi/v3/campaigns").exists()
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {table: db.execute("select count(*) from " + table).fetchone()[0] if table in tables else 0
                  for table in ["finding_observations", "review_decisions", "investigation_call_reservations"]}
        reservations = db.execute("select review from investigation_call_reservations").fetchall()
    assert list(counts.values()) == [0, 0, count], counts
    assert not any(row[0] for row in reservations)
    save(evidence, name + "-check", {"counts": counts, "interceptedRequests": count,
        "liveProviderRequests": 0, "sourceExecuted": False, "sourceUnchanged": True,
        "protectedReviewUnused": True, "newJobs": 0})


def crash(root, evidence):
    assert root == evidence / "fixture-target", "Only this journey's owned fixture may be interrupted"
    row = wait_calls(evidence, 2)[-1]
    assert row["mode"] == "pause"
    run = root / ".kuzushi/v3/runs" / row["runId"]
    metadata = json.loads((run / "run.json").read_text())
    assert metadata["status"] == "running" and metadata["tool"] == base.TOOL
    pid = metadata["processId"]
    native = Path(os.environ["KUZUSHI_NATIVE_BIN"]).resolve()
    images = subprocess.check_output(["lsof", "-a", "-p", str(pid), "-d", "txt", "-Fn"], text=True).splitlines()
    assert any(line.startswith("n") and Path(line[1:]).resolve() == native for line in images)
    command = subprocess.check_output(["ps", "-ww", "-p", str(pid), "-o", "command="], text=True)
    arguments = shlex.split(command)
    target = Path(arguments[arguments.index("--target") + 1]).resolve()
    assert target == root
    save(evidence, "crash-identity", {"pid": pid, "nativePath": str(native),
        "processCommand": command.strip(), "canonicalTarget": str(target)})
    panes = subprocess.check_output(["tmux", "list-panes", "-a", "-F", "#{pane_tty}\t#{pane_current_path}"], text=True).splitlines()
    ttys = [line.split("\t")[0] for line in panes if Path(line.split("\t")[1]).resolve() == root.resolve()]
    assert len(ttys) == 1
    prepared = run / "prepared-model-input.json"
    before = hashlib.sha256(prepared.read_bytes()).hexdigest()
    os.kill(pid, signal.SIGKILL)
    subprocess.run(["stty", "-f" if sys.platform == "darwin" else "-F", ttys[0], "sane"], check=True)
    fd = os.open(ttys[0], os.O_WRONLY | os.O_NOCTTY)
    try:
        os.write(fd, b"\x1b[?1049l\x1b[?25h\x1b[?2004l")
    finally:
        os.close(fd)
    assert hashlib.sha256(prepared.read_bytes()).hexdigest() == before
    (evidence / "interruption-replay-command.txt").write_text("replay " + row["runId"])
    save(evidence, "owned-crash", {"pid": pid, "nativePathVerified": str(native),
        "runId": row["runId"], "preparedInputSha256": before, "liveProviderRequests": 0})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "pause":
        (evidence / "transport-mode.txt").write_text("pause\n")
    elif stage == "crash":
        crash(root, evidence)
    elif stage == "failed":
        stopped(root, evidence, stage, "failed", 1)
    else:
        stopped(root, evidence, stage, "interrupted", 2)
