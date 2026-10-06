"""Labeled synthetic history around the real intercepted usage fixture."""
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
import study_usage

BASELINE = "usage-baseline-trial-001-a1"


def baseline_path(root):
    return root / ".kuzushi/v3/runs" / BASELINE / "run.json"


def seed(root, evidence, home):
    study_usage.seed(root, evidence, home)
    metadata = json.loads(baseline_path(root).read_text())
    (evidence / "baseline-metadata.original").write_bytes(baseline_path(root).read_bytes())
    for index in range(104):
        run_id = f"labeled-synthetic-history-{index:03}"
        directory = root / ".kuzushi/v3/runs" / run_id
        directory.mkdir()
        record = {"runId": run_id, "kind": "labeled-synthetic-history", "status": "completed", "tool": "sast:scan", "target": str(root), "startedAtUnix": metadata["startedAtUnix"] + 100 + index, "completedAtUnix": metadata["startedAtUnix"] + 101 + index, "findings": 0}
        (directory / "run.json").write_text(json.dumps(record) + "\n")
    verify(root, evidence)


def verify(root, evidence):
    study_usage.verify(root, evidence)
    records = list(root.joinpath(".kuzushi/v3/runs").glob("labeled-synthetic-history-*/run.json"))
    assert len(records) == 104
    assert baseline_path(root).read_bytes() == (evidence / "baseline-metadata.original").read_bytes()
    (evidence / "history-check.json").write_text(json.dumps({"labeledSyntheticHistoryRecords": 104, "liveRequests": 0, "selectedOlderBaselinePreserved": True, "baselineMetadataRestored": True}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "break":
        baseline_path(root).write_text("{ labeled malformed metadata for recovery test\n")
    elif stage == "restore":
        baseline_path(root).write_bytes((evidence / "baseline-metadata.original").read_bytes())
    else:
        verify(root, evidence)
