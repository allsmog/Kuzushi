"""Offline Review → Report journey; all observations come from real static scans."""
import json
import os
import sys
from pathlib import Path
sys.dont_write_bytecode = True
from observation_gap import seed, query


def prepare(root, evidence):
    seed(root, evidence)
    rows = query(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, "open")["findings"]
    pending = next(row for row in rows if row["file_path"].endswith("other.env"))
    (evidence / "open-pending.txt").write_text("open " + pending["fingerprint"])


def verify(root, evidence):
    exported = json.loads((root / ".kuzushi/reports/findings.json").read_text())
    if exported["count"] != 2:
        raise RuntimeError("Report must include both fixture findings")
    absent = next(row for row in exported["findings"] if row["location"]["file"] == "config.env")
    pending = next(row for row in exported["findings"] if row["location"]["file"] == "other.env")
    body = json.dumps(pending)
    if "deferred" not in body or "Offline TUI review fixture" not in body:
        raise RuntimeError("Report lost the decision entered through the TUI")
    if absent["observationGap"]["comparedRunId"] != "gap-later":
        raise RuntimeError("Report lost the source-comparison receipt")
    (evidence / "report-check.json").write_text(json.dumps({
        "status": "passed", "findings": 2, "reviewDecisionEnteredInTui": "deferred",
        "sourceComparisonPreserved": True, "providerCalls": 0,
    }, indent=2) + "\n")


if __name__ == "__main__":
    action, target, output = sys.argv[1:]
    {"prepare": prepare, "verify": verify}[action](Path(target).resolve(), Path(output).resolve())
