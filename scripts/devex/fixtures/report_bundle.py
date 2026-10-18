"""Inspect a real Report bundle without changing jobs, source or accounting."""
import hashlib
import json
import sys
from pathlib import Path

import investigation_journey as investigation


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
    verify(root, evidence, sys.argv[3])
