"""Real owned Git revisions and static scans; no model or source execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from context_comparison import commit_source, git, import_context, run_tool, scan_context


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def load(path):
    return json.loads(path.read_text())


def native(root, evidence, label, arguments):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root), *arguments],
                            capture_output=True, text=True, timeout=45, check=False)
    (evidence / (label + ".stdout.json")).write_text(result.stdout)
    (evidence / (label + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def export_history(root, evidence, stage):
    binary = os.environ["KUZUSHI_NATIVE_BIN"]
    output = root / ".kuzushi/reports" / (stage + ".json")
    run_tool(binary, root, evidence, stage + "-json", "workspace:export-findings",
             {"format": "json", "output": str(output)})
    document = load(output)
    assert document["count"] == 1, document
    return document["findings"][0]


def decision(root, evidence, stage, run, verdict, later=None):
    row = export_history(root, evidence, stage)
    assert row["reviewDecision"] == verdict and row["reviewDecisionAuthor"] == "human"
    basis = row["reviewDecisionBasis"]
    assert basis["runId"] == run
    summary = load(root / ".kuzushi/v3/runs" / run / "run.json")
    assert basis["sourceGit"] == summary["targetGit"]
    if later:
        assert basis["laterObservation"]["runId"] == later
        summary = load(root / ".kuzushi/v3/runs" / later / "run.json")
        assert basis["laterObservation"]["sourceGit"] == summary["targetGit"]
        assert basis["sourceApplicability"] == "reassessment_required"
    else:
        assert "laterObservation" not in basis
    save(evidence / (stage + "-basis.json"), basis)
    return basis


def seed(root, evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    (root / "app.py").unlink(missing_ok=True)
    (root / ".gitignore").write_text("# Kuzushi maintains its own state ignore rules.\n")
    (root / "README.md").write_text("Owned offline source-history fixture. The credential-shaped value is an AWS documentation example. No source is executed.\n")
    (root / "main.rs").write_text("// Owned inert source; never compiled or executed.\n")
    git(root, "init", "--quiet", "--initial-branch=main")
    commit_source(root, "Initial owned source fixture")
    reference = import_context(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, "owned-history")
    if git(root, "status", "--porcelain"):
        commit_source(root, "Record owned workspace policy")
    baseline = scan_context(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, "git-base", reference)
    assert baseline["git"]["dirty"] is False
    rows = native(root, evidence, "baseline-findings", ["findings", "--json"])["findings"]
    assert len(rows) == 1, rows
    (evidence / "open.txt").write_text("open " + rows[0]["fingerprint"])
    save(evidence / "state.json", {"context": reference, "runs": [baseline],
        "configHash": hashlib.sha256((root / "config.env").read_bytes()).hexdigest()})


def committed(root, evidence):
    decision(root, evidence, "baseline-confirmed", "git-base", "confirmed")
    state = load(evidence / "state.json")
    (root / "revision-note.txt").write_text("Owned additional source revision; cited file is unchanged.\n")
    commit_source(root, "Add owned source revision note")
    later = scan_context(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, "git-committed", state["context"])
    assert state["runs"][0]["git"]["sha"] != later["git"]["sha"]
    assert hashlib.sha256((root / "config.env").read_bytes()).hexdigest() == state["configHash"]
    state["runs"].append(later)
    save(evidence / "state.json", state)
    basis = decision(root, evidence, "committed-history", "git-base", "confirmed", "git-committed")
    assert basis["sourceComparison"] == "same_cited_source"
    assert basis["sourceChangedSinceDecision"] is False


def dirty(root, evidence):
    state = load(evidence / "state.json")
    with (root / "config.env").open("a") as source:
        source.write("# Owned uncommitted annotation; documentation example unchanged.\n")
    later = scan_context(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, "git-dirty", state["context"])
    assert later["git"]["sha"] == state["runs"][-1]["git"]["sha"]
    assert later["git"]["dirty"] and later["treeHash"] != state["runs"][-1]["treeHash"]
    state["runs"].append(later)
    save(evidence / "state.json", state)
    basis = decision(root, evidence, "dirty-history", "git-base", "confirmed", "git-dirty")
    assert basis["sourceComparison"] == "different_cited_source"
    assert basis["sourceChangedSinceDecision"] is True
    binary = os.environ["KUZUSHI_NATIVE_BIN"]
    sarif = root / ".kuzushi/reports/history.sarif"
    run_tool(binary, root, evidence, "confirmed-sarif", "report:sarif", {"output": str(sarif)})
    properties = load(sarif)["runs"][0]["results"][0]["properties"]
    assert properties["kuzushiReviewDecisionBasis"] == basis
    assert properties["kuzushiCurrentCheckoutApplicability"] == "not_assessed"
    bundle = root / ".kuzushi/reports/history-bundle"
    run_tool(binary, root, evidence, "history-markdown", "workspace:export-findings",
             {"format": "markdown-bundle", "output": str(bundle)})
    body = "\n".join(path.read_text() for path in bundle.rglob("*.md"))
    assert basis["sourceGit"]["sha"] in body and later["git"]["sha"] in body
    assert "dirty" in body and "applicability not assessed" in body


def gap(root, evidence):
    decision(root, evidence, "dirty-deferred", "git-dirty", "deferred")
    state = load(evidence / "state.json")
    (root / "config.env").write_text("# Owned documentation example removed; absence is not proof of a fix.\n")
    output = run_tool(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, "git-gap", "sast:scan", {
        "taskMode": "manual", "tasks": ["secret-scan"], "threatModelRef": state["context"],
        "triage": False, "verify": False, "autoPatch": False,
    }, "git-gap")
    assert output["data"]["coreFindings"] == []
    summary = load(root / ".kuzushi/v3/runs/git-gap/run.json")
    assert summary["targetGit"]["sha"] == state["runs"][-1]["git"]["sha"]
    assert summary["targetGit"]["dirty"]
    state["runs"].append({"runId":"git-gap", "git":summary["targetGit"],
        "treeHash":output["data"]["treeHash"], "findings":0})
    save(evidence / "state.json", state)
    row = export_history(root, evidence, "gap-history")
    assert row["reviewDecision"] == "deferred"
    assert row["observationGap"]["lastSeenRunId"] == "git-dirty"
    assert row["observationGap"]["comparedRunId"] == "git-gap"
    assert "Absence does not establish a fix" in row["observationNote"]
    for status in ["fixed", "removed"]:
        result = run_tool(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, "query-" + status,
                          "findings:list", {"state":[status]})
        assert result["data"]["count"] == 0
    save(evidence / "source-final.json", {name:hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ["config.env", "main.rs", "README.md", "revision-note.txt"]})


def verify(root, evidence, stage):
    state = load(evidence / "state.json")
    assert len(state["runs"]) == 4 and [run["findings"] for run in state["runs"]] == [1,1,1,0]
    assert load(root / ".kuzushi/threat-models/manifest.json")["active"] == state["context"]
    decision(root, evidence, stage, "git-dirty", "deferred")
    source = {name:hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ["config.env", "main.rs", "README.md", "revision-note.txt"]}
    assert source == load(evidence / "source-final.json")
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 3
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 2
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts"]:
            if table in tables: assert db.execute("select count(*) from " + table).fetchone()[0] == 0
    save(evidence / (stage + "-check.json"), {"actualGitRevisions":True,"scans":4,
        "observations":3,"humanDecisions":2,"providerRequests":0,"sourceExecuted":False,
        "findingEngine":"secret-scan","credentialIsDocumentationExample":True,
        "sourceAfterPlannedEditsUnchanged":True})


root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
if stage in ["seed", "committed", "dirty", "gap"]:
    {"seed":seed,"committed":committed,"dirty":dirty,"gap":gap}[stage](root, evidence)
else:
    verify(root, evidence, stage)
