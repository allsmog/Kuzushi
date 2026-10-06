"""Verify a real bounded study report using intercepted provider transport."""
import json
import os
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
import study_limit
import study_execution


def verify_receipt(root, receipt):
    plan = study_execution.load_plan(root)
    fixture = json.loads((root / ".kuzushi/v3/context-map-fixture.json").read_text())
    assert receipt["schemaVersion"] == 1 and receipt["campaignId"] == plan["campaignId"]
    work = receipt["occurrence"]
    assert (work["completed"], work["planned"], work["failed"], work["pending"]) == (2, 3, 1, 0)
    assert len(work["rows"]) == 1 and work["rows"][0]["seen"] == 2
    assert (receipt["findingCount"], receipt["observationCount"], receipt["reviewedCount"]) == (1, 2, 1)
    assert receipt["equivalence"]["components"]["threatModel"] == fixture["generated"]
    assert receipt["equivalence"]["components"]["model"] == "openai-codex:gpt-5.5"
    assert receipt["scope"]["tasks"] == ["agentic"]
    assert len(receipt["attempts"]) == 3
    assert all(attempt["sourceIdentity"]["kind"] != "unavailable" for attempt in receipt["attempts"])
    accounting = receipt["allowance"]["currentInvestigation"]
    assert accounting["limits"] == {"maxProviderCalls": 5, "protectedReviewCalls": 2}
    assert accounting["committedCalls"] == 3 and accounting["unresolvedCalls"] == 0
    assert accounting["cost"]["completeness"] == "unavailable"
    assert accounting["cost"]["observedUsd"] is None
    assert any("never establishes a fix" in limitation for limitation in receipt["limitations"])
    return plan


def verify_report(root, evidence):
    study_limit.verify_report(root, evidence)
    report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
    plan = verify_receipt(root, report["metadata"]["investigation"])
    assert report["metadata"]["findingSelection"] == {"kind": "study", "campaignId": plan["campaignId"]}
    adjacent = json.loads((root / ".kuzushi/reports/findings.json.investigation.json").read_text())
    assert adjacent == report["metadata"]["investigation"]
    (evidence / "report-receipt-verification.json").write_text(json.dumps({
        "completedJobs": 2, "failedJobs": 1, "observations": 2, "distinctFindings": 1,
        "acceptedContextPreserved": True, "sourceIdentitiesPresent": True,
        "unknownDollars": True, "protectedReviewCalls": 2,
        "liveProviderCalls": 0, "findingsAreSynthetic": True,
    }, indent=2) + "\n")


def verify_formats(root, evidence):
    binary = os.environ["KUZUSHI_NATIVE_BIN"]
    campaign = study_execution.load_plan(root)["campaignId"]
    for fmt, name in [("json", "receipt.json"), ("jsonl", "receipt.jsonl"),
                      ("sarif", "receipt.sarif"), ("csv", "receipt.csv"),
                      ("vuln-findings", "receipt-vuln.json"), ("markdown-bundle", "receipt-bundle")]:
        output = root / ".kuzushi/reports" / name
        result = subprocess.run([binary, "--target", str(root), "export", "--campaign-id", campaign,
                                 "--format", fmt, "--out", str(output), "--allow-empty"],
                                text=True, capture_output=True, timeout=30, check=True)
        assert "investigation receipt:" in result.stdout
        receipt_path = output / "investigation.json" if fmt == "markdown-bundle" else Path(str(output) + ".investigation.json")
        verify_receipt(root, json.loads(receipt_path.read_text()))
    study_limit.verify_selection(root, evidence, True)


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "report":
        verify_report(root, evidence)
    elif action == "formats":
        verify_formats(root, evidence)
    else:
        raise ValueError(action)
