"""Read completed live work after an owned source change, without new scans."""
import hashlib
import json
import sys
from pathlib import Path

from live_investigation import CONTROL, FIXTURE, OWNER, SCAN, git, native, save, sources
from secret_settings import ledger

BRANCH = "revision-reading-20261010"
STATE = FIXTURE / "control/source-revision-reading.json"


def counts(root, evidence):
    tables = ["investigation_call_reservations", "investigation_work_attempts",
              "finding_observations", "review_decisions"]
    with ledger(root, evidence) as db:
        return {table: db.execute("select count(*) from " + table).fetchone()[0]
                for table in tables}


def check_owner_config(before):
    path = OWNER / ".kuzushi/v3/config.toml"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before["operatorConfigSha256"]


def prepare(root, evidence):
    assert root == FIXTURE / "target" and not STATE.exists()
    before = json.loads((CONTROL / "source-before.json").read_text())
    assert git(root, "branch", "--show-current") == "main"
    assert git(root, "rev-parse", "HEAD") == before["sha"]
    assert sources(root) == before["files"] and not git(root, "status", "--porcelain=v1")
    check_owner_config(before)
    baseline = json.loads((root / ".kuzushi/reports/findings.json").read_text())
    state = {"before": before, "counts": counts(root, evidence), "report": baseline}
    git(root, "switch", "-c", BRANCH)
    with (root / "greeting.py").open("a") as output:
        output.write("# Owned revision reading check. Source remains inert.\n")
    git(root, "add", "greeting.py")
    git(root, "commit", "-m", "test: record source revision reading fixture")
    state.update(sha=git(root, "rev-parse", "HEAD"), files=sources(root))
    assert state["sha"] != before["sha"]
    assert state["files"]["public-example.env"] == before["files"]["public-example.env"]
    save(STATE.parent, STATE.stem, state)
    save(evidence, "revision-prepared", {key: state[key] for key in ["sha", "files", "counts"]})


def verify(root, evidence, stage):
    assert root == FIXTURE / "target"
    state = json.loads(STATE.read_text())
    assert git(root, "branch", "--show-current") == BRANCH
    assert git(root, "rev-parse", "HEAD") == state["sha"]
    assert sources(root) == state["files"] and not git(root, "status", "--porcelain=v1")
    check_owner_config(state["before"])
    assert counts(root, evidence) == state["counts"]
    report = export(root, evidence, stage)
    finding = report["findings"][0]
    assert finding["reviewDecisionBasis"] == state["report"]["findings"][0]["reviewDecisionBasis"]
    assert report["metadata"]["investigation"] == state["report"]["metadata"]["investigation"]
    save(evidence, stage + "-verified", {"currentSha": state["sha"],
         "recordedSha": state["before"]["sha"], "citedFileUnchanged": True,
         "counts": state["counts"], "currentSourceApplicability": "not_assessed"})


def export(root, evidence, stage):
    output = root / ".kuzushi/reports" / ("revision-reading-" + stage + ".json")
    native(root, evidence, stage + "-export", "workspace:export-findings",
           {"campaignId": SCAN, "format": "json", "output": str(output)})
    report = json.loads(output.read_text())
    assert report["count"] == 1
    assert report["metadata"]["currentCheckoutApplicability"] == "not_assessed"
    return report


def restore(root, evidence):
    verify(root, evidence, "before-restore")
    state = json.loads(STATE.read_text())
    git(root, "switch", "main")
    assert git(root, "rev-parse", "HEAD") == state["before"]["sha"]
    assert sources(root) == state["before"]["files"]
    save(evidence, "baseline-restored", {"sha": state["before"]["sha"],
         "retainedRevisionBranch": BRANCH, "retainedRevisionSha": state["sha"]})


def formats(root, evidence):
    verify(root, evidence, "formats")
    expected = json.loads(STATE.read_text())["report"]["metadata"]["investigation"]
    for kind in ["jsonl", "sarif", "markdown-bundle"]:
        output = root / ".kuzushi/reports" / ("revision-reading-formats." + kind)
        native(root, evidence, "format-" + kind, "workspace:export-findings",
               {"campaignId": SCAN, "format": kind, "output": str(output)})
        if kind == "jsonl":
            metadata = json.loads(output.read_text().splitlines()[0])["metadata"]
        elif kind == "sarif":
            metadata = json.loads(output.read_text())["properties"]["kuzushiExport"]
        else:
            metadata = json.loads((output / "manifest.json").read_text())["metadata"]
        assert metadata["currentCheckoutApplicability"] == "not_assessed"
        assert metadata["investigation"] == expected
    assert counts(root, evidence) == json.loads(STATE.read_text())["counts"]
    save(evidence, "formats-verified", {"formats": ["json", "jsonl", "sarif", "markdown-bundle"],
         "currentCheckoutApplicability": "not_assessed", "historicalInvestigationUnchanged": True})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    evidence.mkdir(parents=True, exist_ok=True)
    stage = sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence)
    elif stage == "restore":
        restore(root, evidence)
    elif stage == "formats":
        formats(root, evidence)
    else:
        verify(root, evidence, stage)
