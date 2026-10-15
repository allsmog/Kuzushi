"""Export existing owned three-pass history without scans or model requests."""
import json
import sys
import tempfile
from pathlib import Path

from live_investigation import CONTROL, FIXTURE, SCAN, git, native, sources
from live_source_revision import check_owner_config, counts
from secret_settings import save


def verify(root, evidence):
    assert root == FIXTURE / "target"
    before = json.loads((CONTROL / "source-before.json").read_text())
    assert git(root, "branch", "--show-current") == "main"
    assert git(root, "rev-parse", "HEAD") == before["sha"]
    assert sources(root) == before["files"] and not git(root, "status", "--porcelain=v1")
    check_owner_config(before)
    assert counts(root, evidence) == {"investigation_call_reservations":4,
        "investigation_work_attempts":6,"finding_observations":3,"review_decisions":1}


def exports(root, evidence):
    verify(root, evidence)
    reports = root / ".kuzushi/reports"
    reports.mkdir(parents=True, exist_ok=True)
    destination = Path(tempfile.mkdtemp(prefix="source-history-", dir=reports))
    expected = None
    for kind in ["json", "jsonl", "sarif", "markdown-bundle"]:
        output = destination / kind
        native(root, evidence, "export-" + kind, "workspace:export-findings",
            {"campaignId":SCAN,"format":kind,"output":str(output)})
        if kind == "json":
            report = json.loads(output.read_text())
            finding = report["findings"][0]
            history = finding["provenance"]["sourceHistory"]
            assert finding["evidence"]["sourceCount"] == 1
            assert finding["evidence"]["state"] != "corroborated"
            assert finding["reviewDecisionAuthor"] == "human"
            assert finding["reviewDecisionBasis"]["sourceGit"]["sha"] == json.loads((CONTROL / "source-before.json").read_text())["sha"]
        elif kind == "jsonl":
            lines = output.read_text().splitlines()
            finding = json.loads(lines[1])
            history = finding["provenance"]["sourceHistory"]
        elif kind == "sarif":
            report = json.loads(output.read_text())
            history = report["runs"][0]["results"][0]["properties"]["kuzushiSourceHistory"]
        else:
            manifest = json.loads((output / "manifest.json").read_text())
            history = manifest["findings"][0]["sourceHistory"]
            text = (output / manifest["findings"][0]["path"]).read_text()
            assert "Recorded source summaries" in text
            assert all(item["lastScanId"] in text for item in history)
        assert len(history) == 3
        assert len({item["lastScanId"] for item in history}) == 3
        if expected is None: expected = history
        assert history == expected
    verify(root, evidence)
    save(evidence, "export-history-verified", {"formats":["json","jsonl","sarif","markdown-bundle"],
        "sourceSummaries":3,"distinctSources":1,"providerRequestsAdded":0,
        "sourceExecuted":False,"sourceUnchanged":True,"decisionPreserved":True})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    evidence.mkdir(parents=True, exist_ok=True)
    {"exports":exports,"verify":verify}[sys.argv[3]](root, evidence)
