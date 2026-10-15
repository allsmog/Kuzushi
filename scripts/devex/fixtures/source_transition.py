"""Owned real revisions and static observations. Never execute target source."""
import json
import os
import subprocess
import sys
from pathlib import Path

from catalog_dependencies import SOURCE, SHA, git, source_files
from secret_settings import ledger, save

LATER_SHA = "30baa1f1a56bae4cbb431ba0d453a59a8108a71b"
BASE = "revision-base-003"
LATER = "revision-later"
ABSENT = "revision-absent"
NARROW = "revision-narrow"


def command(root, evidence, name, args, value=None):
    env = dict(os.environ, HOME=str(evidence / "home"))
    for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY", "GEMINI_API_KEY",
                "KUZUSHI_MODEL", "NODE_OPTIONS", "KUZUSHI_LANGGRAPH_BRIDGE"]:
        env.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root), *args],
        input=json.dumps(value) if value is not None else None, env=env,
        capture_output=True, text=True, timeout=60)
    (evidence / (name + ".stdout.txt")).write_text(result.stdout)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, (name, result.returncode, result.stderr)
    return result.stdout


def scan(root, evidence, run_id, paths=None):
    options = {"taskMode":"manual", "tasks":["secret-scan"], "triage":False,
               "verify":False, "autoPatch":False, "threatModelRef":None}
    if paths is not None:
        options["paths"] = paths
    result = json.loads(command(root, evidence, run_id,
        ["run", "sast:scan", "--run-id", run_id, "--input", "-"], options))
    assert result["status"] == "completed", result
    run = root / ".kuzushi/v3/runs" / run_id
    summary = json.loads((run / "run.json").read_text())
    findings = json.loads((run / "findings.json").read_text())
    assert findings == result["data"]["coreFindings"]
    return {"runId":run_id, "git":summary["targetGit"],
            "treeHash":result["data"]["treeHash"], "observations":len(findings)}


def seed(parent, evidence, home):
    root = parent / "repository"
    assert not root.exists() and home == (evidence / "home").resolve()
    assert git(SOURCE, "branch", "--show-current") == "main" and git(SOURCE, "rev-parse", "HEAD") == SHA
    subprocess.run(["git", "clone", "--local", "--no-hardlinks", "--branch", "main",
                    str(SOURCE), str(root)], capture_output=True, check=True)
    assert git(root, "rev-parse", "origin/revision-reading-20261010") == LATER_SHA
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    save(evidence, "source-before", {"sha":SHA,"files":source_files(root)})
    runs = [scan(root, evidence, "revision-base-00" + str(i)) for i in range(1, 4)]
    assert all(run["git"]["sha"] == SHA and not run["git"]["dirty"] and run["observations"] == 1 for run in runs)
    assert len({run["treeHash"] for run in runs}) == 1
    save(evidence, "recorded-runs", runs)


def advance(parent, evidence):
    root = parent / "repository"
    assert git(root, "rev-parse", "HEAD") == SHA and not git(root, "status", "--porcelain=v1")
    with ledger(root, evidence) as db:
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 1
    git(root, "switch", "--detach", LATER_SHA)
    original = (root / "public-example.env").read_bytes()
    runs = json.loads((evidence / "recorded-runs.json").read_text())
    runs.append(scan(root, evidence, LATER))
    (root / "public-example.env").write_text("# Owned public documentation example temporarily omitted for presence inspection.\n")
    runs.append(scan(root, evidence, ABSENT))
    (root / "public-example.env").write_bytes(original)
    (root / "scoped").mkdir()
    (root / "scoped/note.md").write_text("Owned inert scope. No target execution.\n")
    runs.append(scan(root, evidence, NARROW, ["scoped"]))
    assert [run["observations"] for run in runs] == [1,1,1,1,0,0]
    assert all(run["git"]["sha"] == LATER_SHA for run in runs[3:])
    assert not runs[3]["git"]["dirty"] and all(run["git"]["dirty"] for run in runs[4:])
    assert len({run["treeHash"] for run in runs[2:]}) == 4
    save(evidence, "recorded-runs", runs)
    save(evidence, "source-after", {"sha":LATER_SHA,"files":source_files(root)})


def verify(parent, evidence):
    root = parent / "repository"
    assert git(root, "rev-parse", "HEAD") == LATER_SHA
    assert source_files(root) == json.loads((evidence / "source-after.json").read_text())["files"]
    comparisons = [(BASE,LATER,"seen_again"),(LATER,ABSENT,"not_observed"),(BASE,NARROW,"not_reassessed")]
    for left,right,status in comparisons:
        name = "comparison-" + right
        data = json.loads(command(root,evidence,name,["runs","diff",left,right,"--json"]))
        assert data["observationSchemaVersion"] == 1
        assert len(data["observationPresence"]) == 1, data
        assert data["observationPresence"][0]["status"] == status
        assert data["observationPresence"][0]["fixStatus"] == "not_assessed"
        assert data["decisionSummary"]["carryForwardIsSourceApproval"] is False
        assert data["decisionSummary"]["sourceApplicability"] == "not_assessed"
        assert data["baseSource"]["git"]["sha"] in [SHA,LATER_SHA]
        assert data["compareSource"]["git"]["sha"] == LATER_SHA
        plain = command(root,evidence,name + "-plain",["runs","diff",left,right])
        assert "Absence does not establish a fix." in plain and "resolved=" not in plain and "Resolved:" not in plain
        assert "carry_forward=" not in plain
    with ledger(root,evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name:db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0 for name in
            ["finding_observations","review_decisions","investigation_call_reservations","investigation_work_attempts","investigation_allowance_revisions"]}
    assert list(counts.values()) == [4,1,0,0,0], counts
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    output = root / ".kuzushi/reports/source-transition.json"
    command(root,evidence,"recorded-report",["run","workspace:export-findings","--input","-"],
            {"format":"json","output":str(output)})
    report = json.loads(output.read_text())
    assert report["count"] == 1
    finding = report["findings"][0]
    assert finding["reviewDecision"] == "rejected_false_positive"
    basis = finding["reviewDecisionBasis"]
    assert basis["runId"] == BASE and basis["sourceGit"]["sha"] == SHA
    assert basis["laterObservation"]["runId"] == LATER
    assert basis["laterObservation"]["sourceGit"]["sha"] == LATER_SHA
    assert basis["sourceApplicability"] == "reassessment_required"
    assert finding["provenance"]["sourceHistory"]
    save(evidence,"recorded-report",report)
    save(evidence,"transition-invariants",{"counts":counts,"providerRequests":0,"sourceExecuted":False,"newCommits":0})


if __name__ == "__main__":
    parent,evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    action = sys.argv[3]
    if action == "seed":
        seed(parent,evidence,Path(sys.argv[4]).resolve())
    elif action == "advance":
        advance(parent,evidence)
    else:
        verify(parent,evidence)
