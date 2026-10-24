"""Inspect a real Report bundle without changing jobs, source or accounting."""
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import investigation_journey as investigation


def report_pane(root):
    output = subprocess.check_output(["tmux", "list-panes", "-a", "-F",
        "#{session_name}\t#{pane_id}\t#{pane_current_path}"], text=True)
    matches = [pane for line in output.splitlines()
        for session, pane, cwd in [line.split("\t", 2)]
        if session.startswith("kzx-devex-j121-") and Path(cwd).resolve() == root]
    assert len(matches) == 1, "Expected exactly one owned Report journey pane"
    return matches[0]


def retry_export_if_ready(root, evidence):
    pane = report_pane(root)
    deadline = time.monotonic() + 25
    presses = 0
    while time.monotonic() < deadline:
        text = subprocess.check_output(["tmux", "capture-pane", "-p", "-t", pane], text=True)
        header = text.splitlines()[1]
        if header.startswith("EXPORTED ·"):
            (evidence / "bundle-retry-action.json").write_text(json.dumps({
                "additionalEnterPresses": presses, "automaticExportQueued": False,
                "modelRequestsAdded": 0, "sourceExecuted": False}) + "\n")
            return
        if header.startswith("RETRY EXPORT ·") and presses == 0:
            subprocess.run(["tmux", "send-keys", "-t", pane, "Enter"], check=True)
            presses += 1
        time.sleep(0.05)
    raise AssertionError("The explicit Report export did not complete; do not relaunch it")


def verify(root, evidence, stage):
    investigation.verify(root, evidence, "final-report")
    bundle = root / ".kuzushi/reports/study-bundle"
    assert not list(root.glob(".kuzushi-report-*"))
    assert not list(bundle.parent.glob(".kuzushi-report-*"))
    if stage == "blocked":
        assert not bundle.exists()
        return
    manifest = json.loads((bundle / "manifest.json").read_text())
    receipt = json.loads((bundle / "investigation.json").read_text())
    previous = json.loads((bundle.parent / "findings.json").read_text())
    assert manifest["count"] == manifest["totalCount"] == 2
    assert {row["reviewDecision"] for row in manifest["findings"]} == {"deferred", "rejected_false_positive"}
    assert receipt == manifest["metadata"]["investigation"] == previous["metadata"]["investigation"]
    assert receipt["observationCount"] == 4 and receipt["findingCount"] == 2
    assert receipt["occurrence"]["completed"] == receipt["occurrence"]["planned"] == 3
    assert receipt["occurrence"]["pending"] == 0 and len(receipt["attempts"]) == 4
    usage = receipt["allowance"]["currentInvestigation"]
    assert usage["committedCalls"] == 5 and usage["unresolvedCalls"] == 1
    assert usage["limits"] == {"maxProviderCalls": 7, "protectedReviewCalls": 2}
    assert usage["reviewCalls"] == 0 and usage["cost"]["observedUsd"] is None
    assert usage["cost"]["completeness"] == "unavailable"
    for entry in manifest["files"]:
        path = bundle / entry["path"]
        assert path.resolve().is_relative_to(bundle.resolve()) and path.is_file()
        assert entry["sha256"] == "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    assert ".kuzushi-report-" not in (bundle / "manifest.json").read_text()
    assert "(investigation.json)" in (bundle / "README.md").read_text()
    proof = {"files": {str(p.relative_to(bundle)): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in bundle.rglob("*") if p.is_file()},
        "sourceUnchanged": True, "fixedJobs": 3, "observations": 4, "findings": 2,
        "committedCalls": 5, "unresolvedCalls": 1, "protectedReviewUnused": 2,
        "newLiveRequests": 0, "sourceExecuted": False}
    path = evidence / "bundle-exported.json"
    if stage == "restart":
        assert proof == json.loads(path.read_text())
    else:
        assert stage == "exported"
        path.write_text(json.dumps(proof, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "retry-export":
        retry_export_if_ready(root, evidence)
    else:
        verify(root, evidence, stage)
