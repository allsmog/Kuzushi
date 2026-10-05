"""Real offline scans and a labeled review decision; no provider calls."""
import csv
import json
import os
import subprocess
import sys
from pathlib import Path
sys.dont_write_bytecode = True
from context_comparison import commit_source, git, run_tool, scan_context


def record_confirmation(binary, root, evidence, fingerprint):
    result = subprocess.run([
        binary, "--target", str(root), "decision", fingerprint,
        "--verdict", "confirmed", "--reason", "Labeled offline review fixture", "--json",
    ], text=True, capture_output=True, timeout=30, check=True)
    (evidence / "decision.json").write_text(result.stdout)
    if json.loads(result.stdout)["verdict"] != "confirmed":
        raise RuntimeError("Fixture confirmation was not recorded")


def query(binary, root, evidence, state):
    return run_tool(binary, root, evidence, "query-" + state,
                    "findings:list", {"state": [state]})["data"]


def check_exports(binary, root, evidence, gap):
    for format_name in ["json", "jsonl", "sarif", "csv", "markdown-bundle", "vuln-findings"]:
        path = root / ".kuzushi/v3/reports" / ("gap-" + format_name)
        run_tool(binary, root, evidence, "export-" + format_name,
                 "workspace:export-findings", {"format": format_name, "output": str(path)})
        if path.is_dir():
            body = "\n".join(p.read_text() for p in path.rglob("*") if p.is_file())
        else:
            body = path.read_text()
        for value in [gap["eventHash"], "gap-base", "gap-later", "Absence does not establish a fix."]:
            if value not in body:
                raise RuntimeError(f"{format_name} lost observation provenance: {value}")
        if format_name == "csv":
            rows = list(csv.DictReader(body.splitlines()))
            absent = [row for row in rows if row["observation_compared_run_id"] == "gap-later"]
            if len(absent) != 1 or absent[0]["review_decision"] != "confirmed":
                raise RuntimeError("CSV lost the confirmation beside the observation gap")
    run_tool(binary, root, evidence, "confirmed-sarif", "report:sarif", {})
    report = (root / ".kuzushi/v3/reports/confirmed-findings.sarif").read_text()
    if gap["eventHash"] not in report:
        raise RuntimeError("Confirmed SARIF lost the observation gap")


def seed(root, evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    binary = os.environ["KUZUSHI_NATIVE_BIN"]
    git(root, "init", "--quiet", "--initial-branch=main")
    (root / ".gitignore").write_text("# Kuzushi maintains state ignore rules.\n")
    commit_source(root, "Initial labeled source fixture")
    base = scan_context(binary, root, evidence, "gap-base", None)
    rows = query(binary, root, evidence, "open")["findings"]
    original = next(row for row in rows if row["file_path"].endswith("config.env"))
    record_confirmation(binary, root, evidence, original["fingerprint"])
    # Move the existing documentation-example fixture to a different source path.
    # No real credential is created; the later engine still has a positive control.
    (root / "other.env").write_bytes((root / "config.env").read_bytes())
    (root / "config.env").write_text("# Documentation-example fixture removed in this revision.\n")
    commit_source(root, "Move labeled fixture to a separate file")
    later = scan_context(binary, root, evidence, "gap-later", None)
    absent = query(binary, root, evidence, "not_observed")
    if absent["count"] != 1:
        raise RuntimeError("Expected exactly one recorded observation gap")
    row = absent["findings"][0]
    gap = row["observation_gap"]
    if row["fingerprint"] != original["fingerprint"] or row["review_decision"] != "confirmed":
        raise RuntimeError("Later absence changed the finding identity or confirmation")
    if gap["lastSeenRunId"] != "gap-base" or gap["comparedRunId"] != "gap-later":
        raise RuntimeError("Observation gap lost the real run pair")
    for state in ["fixed", "removed"]:
        if query(binary, root, evidence, state)["count"]:
            raise RuntimeError("Absence falsely closed a finding")
    if base["git"]["sha"] == later["git"]["sha"]:
        raise RuntimeError("The fixture must compare distinct committed revisions")
    check_exports(binary, root, evidence, gap)
    (evidence / "open-command.txt").write_text("open " + original["fingerprint"])
    (evidence / "receipt.json").write_text(json.dumps({
        "status": "passed", "runs": [base, later], "observationGap": gap,
        "reviewDecision": "confirmed", "providerCalls": 0,
        "source": "labeled offline fixture", "exportsChecked": 7,
    }, indent=2) + "\n")


if __name__ == "__main__":
    seed(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
