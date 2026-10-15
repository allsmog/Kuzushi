"""Owned context text and process-crash recovery. Never execute target source."""
import hashlib
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import context_case_edit

TEXT = "Checkpoint α\nsecond line 東京"
EDITED = "Chckpoint α\nsecond line 東京"


def records(home, root):
    result = []
    for path in (home / ".kuzushi/v3/context-drafts").glob("*/*.json"):
        value = json.loads(path.read_text())
        if value["target"] == str(root.resolve()):
            result.append((path, value))
    return result


def invariant(root, evidence):
    import bounded_semgrep
    assert bounded_semgrep.source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text()).get("active") is None
    counts = context_case_edit.count_rows(root, evidence)
    assert all(value in [None, 0] for value in counts.values()), counts
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))


def checkpoint(root, evidence, home, expected):
    invariant(root, evidence)
    found = [(p, v) for p, v in records(home, root) if v["snapshot"]]
    assert found
    matching = [(p, v) for p, v in found if any(f["pointer"] == "/systemContext" and f["text"] == expected for f in v["snapshot"]["fields"])]
    assert matching, "Expected exact checkpoint text was not published"
    return matching[-1]


def crash(root, evidence, home):
    path, draft = checkpoint(root, evidence, home, TEXT)
    assert draft["snapshot"]["fields"][0]["cursor"] == 2
    crash_owned_shell(root, evidence, home, path, draft)


def crash_owned_shell(root, evidence, home, path, draft):
    sessions = list((home / ".kuzushi/v3/sessions").glob("*/*/*/session-*.jsonl"))
    starts = [json.loads(p.read_text().splitlines()[0]) for p in sessions]
    start = next(v for v in starts if v["sessionId"] == draft["sessionId"])
    metadata = start["payload"]
    assert Path(metadata["initialTarget"]).resolve() == root.resolve()
    pid = metadata["processId"]
    command = subprocess.check_output(["ps", "-p", str(pid), "-o", "command="], text=True).strip()
    proofs = [json.loads(p.read_text()) for p in evidence.glob("*.provenance.json")]
    native = proofs[-1]["native_resolved_path"]
    images = subprocess.check_output(["lsof", "-a", "-p", str(pid), "-d", "txt", "-Fn"], text=True).splitlines()
    assert any(row.startswith("n") and Path(row[1:]).resolve() == Path(native).resolve() for row in images), "Owned fixture executable identity was not confirmed"
    assert str(root) in command or str(root.resolve()) in command
    panes = subprocess.check_output(["tmux", "list-panes", "-a", "-F", "#{pane_tty}\t#{pane_current_path}"], text=True).splitlines()
    ttys = [row.split("\t")[0] for row in panes if Path(row.split("\t")[1]).resolve() == root.resolve()]
    assert len(ttys) == 1
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    os.kill(pid, signal.SIGKILL)
    subprocess.run(["stty", "-f" if sys.platform == "darwin" else "-F", ttys[0], "sane"], check=True)
    fd = os.open(ttys[0], os.O_WRONLY | os.O_NOCTTY)
    try:
        os.write(fd, b"\x1b[?1049l\x1b[?25h\x1b[?2004l")
    finally:
        os.close(fd)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    (evidence / "crash-receipt.json").write_text(json.dumps({"ownedFixtureProcessKilled": True, "pid": pid, "checkpointSha256": before, "sourceExecuted": False, "providerRequests": 0}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, home = [Path(value) for value in sys.argv[1:4]]
    stage = sys.argv[4]
    if stage == "seed":
        context_case_edit.seed(root, evidence, home)
        (evidence / "checkpoint-text.txt").write_text(TEXT)
    elif stage == "crash":
        crash(root, evidence, home)
    elif stage == "edited":
        checkpoint(root, evidence, home, EDITED)
    else:
        invariant(root, evidence)
        saved = records(home, root)
        resolved = {h for _, value in saved for h in value["resolvedHashes"]}
        assert not any(v["snapshot"] and hashlib.sha256(p.read_bytes()).hexdigest() not in resolved for p, v in saved), "Discard checkpoint is not durable"
