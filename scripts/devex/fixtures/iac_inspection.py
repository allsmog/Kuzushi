"""Owned inert configuration inspection, with no target build or execution."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from catalog_dependencies import SOURCE, SHA, git
from dependency_hygiene import native, tool_results
from secret_settings import ledger, save


def sources(root):
    paths = list((root / "selected").glob("Dockerfile*")) + [root / "Dockerfile"]
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths}


def seed(parent, evidence, home):
    root = parent / "repository"
    assert not root.exists() and home == (evidence / "home").resolve()
    assert git(SOURCE, "branch", "--show-current") == "main" and git(SOURCE, "rev-parse", "HEAD") == SHA
    subprocess.run(["git", "clone", "--local", "--no-hardlinks", "--branch", "main",
                    str(SOURCE), str(root)], capture_output=True, check=True)
    selected = root / "selected"
    selected.mkdir()
    (selected / "Dockerfile").write_text("FROM owned:latest\nUSER nobody\n# Owned inert policy example\n")
    (selected / "Dockerfile.oversized").write_text("#" * 2048)
    (root / "Dockerfile").write_text("FROM excluded:latest\nUSER root\n")
    (selected / "cycle").symlink_to(selected, target_is_directory=True)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    save(evidence, "source-before", {"sha": SHA, "files": sources(root)})
    native(root, evidence, "invalid-limit", "iac-scan:scan", {"maxFileBytes": 0}, (2, 3))
    native(root, evidence, "outside-refused", "iac-scan:scan", {"target": "../outside"}, (2, 3))
    native(root, evidence, "context", "context:build", {"enrichment": False})
    direct = {"target": "selected", "max_file_bytes": 1024, "max_entries": 100, "max_total_bytes": 2048}
    sast = {"taskMode": "manual", "tasks": ["iac-scan"], "paths": ["selected"],
            "iacScanMaxFileBytes": 1024, "iacScanMaxEntries": 100, "iacScanMaxTotalBytes": 2048,
            "triage": False, "verify": False, "autoPatch": False, "threatModelRef": None}
    (evidence / "direct-command.txt").write_text("run iac-scan:scan " + json.dumps(direct))
    (evidence / "scan-command.txt").write_text("run sast:scan " + json.dumps(sast))


def verify(parent, evidence, stage):
    root = parent / "repository"
    before = json.loads((evidence / "source-before.json").read_text())
    assert git(root, "branch", "--show-current") == "main" and git(root, "rev-parse", "HEAD") == SHA
    assert sources(root) == before["files"]
    direct = [row for row in tool_results(root) if "filesScanned" in row.get("data", {})]
    assert len(direct) == 1 and direct[0]["status"] == "partial"
    data = direct[0]["data"]
    assert data["count"] == 1 and data["filesScanned"] == 1 and data["filesSkipped"] == 1
    assert data["inspection"]["symlinksExcluded"] == 1
    assert data["inspection"]["bytesRead"] == 59
    assert data["coverageGaps"]["gaps"][0]["path"] == "Dockerfile.oversized"
    assert data["coreFindings"][0]["file_path"] == "selected/Dockerfile"
    assert len(data["snapshotHash"]) == 64 and len(data["treeHash"]) == 64
    if stage != "partial":
        sast = [row for row in tool_results(root) if "nativeInspections" in row.get("data", {})]
        assert len(sast) == 1 and sast[0]["status"] == "partial"
        receipt = sast[0]["data"]["nativeInspections"][0]
        assert receipt["configuredLimits"]["maxFileBytes"] == 1024
        assert receipt["sharedJobAllowance"]["bytesRead"] == 59
        assert "Dockerfile.oversized" in json.dumps(sast[0])
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
                  for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]}
    assert counts["finding_observations"] == (1 if stage == "partial" else 2), counts
    assert counts["investigation_call_reservations"] == counts["investigation_work_attempts"] == 0
    if stage in ["exported", "restarted"]:
        assert counts["review_decisions"] == 1
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert report["count"] == 1 and report["findings"][0]["location"]["file"] == "selected/Dockerfile"
        finding = report["findings"][0]
        assert finding["evidence"]["sourceCount"] == 1 and finding["evidence"]["state"] != "corroborated"
        assert finding["reviewDecisionAuthor"] == "human"
        assert "Owned image policy requires owner review" in json.dumps(report)
        assert "signal_only" in json.dumps(report) and SHA in json.dumps(report)
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    save(evidence, stage + "-verified", {"sha": SHA, "sourceUnchanged": True,
         "targetSourceExecuted": False, "providerRequests": 0, "counts": counts})


if __name__ == "__main__":
    parent, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        seed(parent, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(parent, evidence, sys.argv[3])
