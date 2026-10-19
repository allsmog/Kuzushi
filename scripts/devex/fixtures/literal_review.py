"""Installed source inspection and literal finding labels across owned Git SHAs."""
import hashlib
import json
import os
import sys
from pathlib import Path

import bounded_semgrep
from context_comparison import run_tool
from owned_source_revisions import BASELINE, LATER, create, git
from secret_settings import ledger

PATHS = [" app /lib.py", "app/lib.py"]


def save(evidence, name, value):
    bounded_semgrep.save(evidence, name, value)


def hashes(target):
    return {name: hashlib.sha256((target / name).read_bytes()).hexdigest() for name in PATHS}


def counts(target, evidence):
    with ledger(target, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        return {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
                for name in ["finding_observations", "review_decisions", "investigation_call_reservations"]}


def scan(target, evidence, run_id):
    inputs = {"taskMode": "manual", "tasks": ["semgrep"], "paths": PATHS,
              "semgrepConfig": [str(evidence / "local-rules.yaml")], "semgrepTimeoutMs": 60000,
              "threatModelRef": None, "triage": False, "verify": False, "autoPatch": False,
              "patch": False, "pocExecution": False, "dynamicAnalysis": False}
    result = run_tool(os.environ["KUZUSHI_NATIVE_BIN"], target, evidence, run_id, "sast:scan", inputs, run_id)
    assert result["status"] == "completed"
    assert sorted(row["file_path"] for row in result["data"]["coreFindings"]) == PATHS
    folder = target / ".kuzushi/v3/runs" / run_id
    summary = json.loads((folder / "run.json").read_text())
    frozen = json.loads((folder / "scan-input.json").read_text())
    assert frozen["paths"] == PATHS and frozen["threatModelRef"] is None
    assert counts(target, evidence)["investigation_call_reservations"] == 0
    return {"runId": run_id, "git": summary["targetGit"], "paths": frozen["paths"], "source": hashes(target)}


def export(target, evidence, stage):
    path = target / ".kuzushi/reports/literal-history.json"
    run_tool(os.environ["KUZUSHI_NATIVE_BIN"], target, evidence, stage + "-export",
             "workspace:export-findings", {"format": "json", "output": str(path)})
    output = json.loads(path.read_text())
    assert output["count"] == 2
    assert sorted(row["location"]["file"] for row in output["findings"]) == PATHS
    assert all(row["lifecycleStatus"] not in ["fixed", "removed"] for row in output["findings"])
    return {row["location"]["file"]: row for row in output["findings"]}


def seed(root, evidence, home):
    bounded_semgrep.seed(root, evidence, home)
    target = root / "owned"
    create(target)
    for name in PATHS:
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('# Owned inert policy text. Never executed.\nprint("OWNER_POLICY_REVIEW")\n')
    base = scan(target, evidence, "literal-base")
    assert base["git"]["sha"] == BASELINE and base["git"]["dirty"]
    save(evidence, "state", {"baseline": base})
    rows = run_tool(os.environ["KUZUSHI_NATIVE_BIN"], target, evidence, "initial-findings", "findings:list", {})["data"]["findings"]
    assert len(rows) == 2
    for row in rows:
        file = row.get("filePath", row.get("file_path"))
        suffix = "spaced" if file == PATHS[0] else "plain"
        (evidence / ("open-" + suffix + ".txt")).write_text("open " + row["fingerprint"])
    (evidence / "filter-spaced.txt").write_text("findings filter files:" + json.dumps([PATHS[0]]))
    save(evidence, "initial-counts", counts(target, evidence))


def later(target, evidence):
    rows = export(target, evidence, "baseline-fp")
    assert rows[PATHS[0]]["reviewDecision"] == "rejected_false_positive"
    assert rows[PATHS[0]]["reviewDecisionBasis"]["runId"] == "literal-base"
    git(target, "switch", "fixture-later")
    with (target / PATHS[1]).open("a") as source:
        source.write("# Owned later observation; the policy marker is unchanged.\n")
    current = scan(target, evidence, "literal-later")
    state = json.loads((evidence / "state.json").read_text())
    assert current["git"]["sha"] == LATER != state["baseline"]["git"]["sha"]
    assert current["source"][PATHS[0]] == state["baseline"]["source"][PATHS[0]]
    assert current["source"][PATHS[1]] != state["baseline"]["source"][PATHS[1]]
    state["later"] = current
    save(evidence, "state", state)
    rows = export(target, evidence, "retained-fp")
    basis = rows[PATHS[0]]["reviewDecisionBasis"]
    assert rows[PATHS[0]]["reviewDecision"] == "rejected_false_positive"
    assert basis["sourceGit"]["sha"] == BASELINE
    assert basis["laterObservation"]["sourceGit"]["sha"] == LATER
    assert basis["sourceApplicability"] == "reassessment_required"
    assert counts(target, evidence) == {"finding_observations": 4, "review_decisions": 1, "investigation_call_reservations": 0}


def verify(target, evidence, stage):
    state = json.loads((evidence / "state.json").read_text())
    assert hashes(target) == state["later"]["source"]
    assert git(target, "rev-parse", "HEAD") == LATER
    assert git(target, "branch", "--show-current") == "fixture-later"
    rows = export(target, evidence, stage)
    expected = "needs_review" if stage == "reopened" else "rejected_false_positive"
    assert rows[PATHS[0]]["reviewDecision"] == expected
    assert rows[PATHS[0]]["reviewDecisionBasis"]["sourceGit"]["sha"] == LATER
    if stage in ["final", "restarted"]:
        assert rows[PATHS[1]]["reviewDecision"] == "deferred"
        assert counts(target, evidence)["review_decisions"] == 4
        exported = json.loads((target / ".kuzushi/reports/findings.json").read_text())
        assert exported["count"] == 2
        assert sorted(row["location"]["file"] for row in exported["findings"]) == PATHS
        assert {row["reviewDecision"] for row in exported["findings"]} == {"rejected_false_positive", "deferred"}
    assert counts(target, evidence)["finding_observations"] == 4
    assert counts(target, evidence)["investigation_call_reservations"] == 0
    save(evidence, stage + "-check", {"baselineSha": BASELINE, "laterSha": LATER,
        "source": hashes(target), "counts": counts(target, evidence), "providerRequests": 0,
        "targetExecuted": False, "newCommits": 0, "rawExportPaths": list(rows)})


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]))
    elif stage == "later":
        later(root / "owned", evidence)
    else:
        verify(root / "owned", evidence, stage)
