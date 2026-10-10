"""Read a large synthetic history replay on the owned completed investigation."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from investigation_report_reader import state


def status(root, evidence, label, input_value):
    started = time.monotonic()
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", "campaign:status", "--input", json.dumps(input_value)], capture_output=True, text=True, timeout=30)
    (evidence / (label + ".json")).write_text(result.stdout)
    (evidence / (label + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value["dataCostScope"] == "projection"
    assert value["data"]["historyWindow"] == {
        "selection": "recent-valid-lines", "maxSnapshots": 90, "maxReadBytes": 1048576}
    assert len(value["data"]["trendHistory"]) == 90
    assert value["data"]["trendHistory"][-1]["providerSpendUnresolved"]
    return time.monotonic() - started


def prepare(root, evidence):
    (evidence / "history-before.json").write_text(json.dumps(state(root), indent=2) + "\n")
    path = root / ".kuzushi/trend-history.jsonl"
    assert path.is_file() and not path.is_symlink() and path.stat().st_size < 1048576
    original = path.read_bytes()
    (evidence / "history-original.bin").write_bytes(original)
    sample = json.loads(original.splitlines()[-1])
    with path.open("wb") as stream:
        stream.truncate(512 * 1024 * 1024)
        stream.seek(0, 2)
        stream.write(b"\n")
        for index in range(100):
            row = {**sample, "tsMs": sample["tsMs"] + index}
            stream.write((json.dumps(row) + "\n").encode())
    campaign = next(json.loads(p.read_text()) for p in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")
        if json.loads(p.read_text())["kind"] == "scan-batch")
    try:
        elapsed = [status(root, evidence, "large-history-all", {}),
            status(root, evidence, "large-history-selected", {"campaignId": campaign["campaignId"]})]
    except BaseException:
        path.write_bytes(original)
        raise
    (evidence / "history-read-receipt.json").write_text(json.dumps({
        "syntheticReplay": True, "sourceExecuted": False, "modelRequestsAdded": 0,
        "historyFileBytes": path.stat().st_size, "elapsedSeconds": elapsed,
        "readerMaxBytes": 1048576, "readerMaxSnapshots": 90}, indent=2) + "\n")


def finish(root, evidence):
    path = root / ".kuzushi/trend-history.jsonl"
    original = (evidence / "history-original.bin").read_bytes()
    try:
        assert state(root) == json.loads((evidence / "history-before.json").read_text())
        captures = list(evidence.glob("*-recent-history-*40x12.txt"))
        joined = " ".join(" ".join(path.read_text().split()) for path in sorted(captures))
        for phrase in ["HISTORY recent", "90 snapshot(s)", "spend >=", "spent (incomplete)"]:
            assert phrase in joined, "Narrow history reader never exposed: " + phrase
        assert len({path.read_text() for path in captures}) > 4, "Narrow history reader did not page"
    finally:
        path.write_bytes(original)
    (evidence / "history-after.json").write_text(json.dumps({"historyRestored": True,
        "sourceUnchanged": True, "newObservations": 0, "newDecisions": 0,
        "newReservations": 0, "newModelRequests": 0}, indent=2) + "\n")


def main():
    assert Path(os.environ.get("KUZUSHI_NATIVE_BIN", "")).is_file(), "Set the built native binary before preparing the replay"
    root, evidence = [Path(value) for value in sys.argv[1:3]]
    if sys.argv[3] == "before":
        prepare(root, evidence)
    else:
        finish(root, evidence)


if __name__ == "__main__":
    main()
