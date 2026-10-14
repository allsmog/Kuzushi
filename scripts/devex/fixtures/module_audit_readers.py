"""Audit operational readers against a completed owned investigation; no model work."""
import json
import os
import subprocess
import sys
from pathlib import Path
from investigation_report_reader import state


def native(root, evidence, label, args):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root), *args],
        capture_output=True, text=True, timeout=30)
    (evidence / (label + ".json")).write_text(result.stdout)
    (evidence / (label + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, label + ": " + result.stderr
    return json.loads(result.stdout)


def prepare(root, evidence):
    (evidence / "audit-before.json").write_text(json.dumps(state(root), indent=2) + "\n")
    all_tools = native(root, evidence, "catalog-all", ["tools", "--all", "--json"])
    defaults = native(root, evidence, "catalog-default", ["tools", "--json"])
    indexed = {tool["name"]: tool for tool in all_tools}
    assert indexed["campaign:status"]["phase"] == "operate"
    assert indexed["campaign:status"]["effect"] == "workspace-write"
    for tool in ["campaign:plan", "campaign:coverage"]:
        assert indexed[tool]["maturity"] == "compatibility"
        assert tool not in {row["name"] for row in defaults}
    plan = next(json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")
        if json.loads(path.read_text())["kind"] == "scan-batch")
    status = native(root, evidence, "status", ["run", "campaign:status", "--input", json.dumps({"campaignId": plan["campaignId"]})])
    assert status["data"]["states"] == {"completed": 3}
    coverage = native(root, evidence, "coverage", ["run", "campaign:coverage", "--input", "{}"])
    assert coverage["data"]["excludedJobs"] == 6
    assert coverage["data"]["columns"] == []
    assert coverage["data"]["coverageMeaning"] == "historical-shard-job-progress"
    report = native(root, evidence, "implicit-report", ["run", "report:build", "--input", "{}"])
    assert report["data"]["sourceTool"] in ["sast:scan", "agentic-sast:scan"]
    assert report["data"]["sourceRunId"] not in [status["data"].get("runId"), coverage["data"].get("runId")]


root, evidence = [Path(value) for value in sys.argv[1:3]]
if sys.argv[3] == "before":
    prepare(root, evidence)
else:
    assert state(root) == json.loads((evidence / "audit-before.json").read_text())
    pages = sorted(evidence.glob("*-progress-*40x12.txt"))
    combined = " ".join(" ".join(path.read_text().split()) for path in pages)
    assert len({path.read_text() for path in pages}) > 1, "The narrow reader did not scroll"
    assert "current-source applicability" in combined
    assert "Accepted scope studies use Report." in combined
    (evidence / "audit-after.json").write_text(json.dumps({"sourceUnchanged": True, "providerRequestsAdded": 0,
        "decisionsAdded": 0, "sourceExecuted": False}, indent=2) + "\n")
