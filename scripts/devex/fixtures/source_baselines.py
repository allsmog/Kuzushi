"""Owned Git metadata audit. Synthetic history, no scan, model or source execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def load(evidence, name):
    return json.loads((evidence / (name + ".json")).read_text())


def git(root, *arguments):
    result = subprocess.run(["git", "-C", str(root), "-c", "core.hooksPath=/dev/null",
        *arguments], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def commit(root, message):
    git(root, "add", ".gitignore", "hello.txt")
    git(root, "-c", "user.name=Owned fixture", "-c", "user.email=fixture@example.test",
        "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", message)
    return git(root, "rev-parse", "HEAD")


def native(root, evidence, label, tool, inputs=None, succeeds=True):
    arguments = [os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root), "run", tool,
        "--input", json.dumps(inputs or {})]
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=40)
    (evidence / (label + ".stdout.json")).write_text(result.stdout)
    (evidence / (label + ".stderr.txt")).write_text(result.stderr)
    if not succeeds:
        assert result.returncode != 0, label
        assert "dirty tree" in result.stderr, result.stderr
        return None
    assert result.returncode == 0, label + ": " + result.stderr
    return json.loads(result.stdout)


def records(root):
    database = root / ".kuzushi/v3/coverage.sqlite3"
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
        return db.execute("select scope_id,phase,mode,run_id,revision_sha,branch,dirty,ts "
            "from scan_baselines order by scope_id,phase,ts").fetchall()


def verdicts(output):
    return {(row["scopeId"], row["phase"]): row["verdict"]
        for row in output["data"]["report"]["entries"]}


def sweep(root, evidence, stage):
    output = native(root, evidence, stage + "-sweep", "coverage:sweep")
    assert output["data"]["scopeCoverageVerified"] is False
    assert output["data"]["findingFixVerified"] is False
    assert "does not establish complete scan coverage or a fixed finding" in output["output"]
    return output


def prepare(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / ".gitignore").write_text("# Workspace maintains local state ignore rules.\n")
    (root / "hello.txt").write_text("Owned inert source metadata fixture. Never executed.\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    native(root, evidence, "empty-baselines", "coverage:baselines")
    git(root, "init", "--quiet", "--initial-branch=main")
    sha = commit(root, "Owned inert source baseline")
    empty = sweep(root, evidence, "unbaselined")
    assert empty["data"]["report"]["unbaselinedScopes"] == ["root"]
    with sqlite3.connect(root / ".kuzushi/v3/coverage.sqlite3") as db:
        rows = [("root", "scan", "synthetic-history", "synthetic-not-a-scan", sha, "main", 0, 100),
            ("root", "map", "synthetic-history", "synthetic-dirty-history", sha, "main", 1, 101),
            ("missing", "scan", "synthetic-history", "synthetic-unavailable-scope", sha, "main", 0, 102)]
        db.executemany("insert into scan_baselines values (?,?,?,?,?,?,?,?)", rows)
    save(evidence, "state", {"home": str(home), "originalSha": sha, "stage": "prepared",
        "configHash": hashlib.sha256(config.read_bytes()).hexdigest(), "records": records(root)})
    output = sweep(root, evidence, "clean")
    expected = {("root", "scan"): {"kind": "current"},
        ("root", "map"): {"kind": "source-unverified", "reason": "dirty-baseline"},
        ("missing", "scan"): {"kind": "source-unverified", "reason": "scope-unavailable"}}
    assert verdicts(output) == expected, verdicts(output)
    baseline = native(root, evidence, "seeded-baselines", "coverage:baselines")
    assert baseline["data"]["scopeCoverageVerified"] is False
    assert sha in baseline["output"] and "synthetic-not-a-scan" in baseline["output"]
    verify(root, evidence, "prepared")


def dirty(root, evidence):
    state = load(evidence, "state")
    (root / "hello.txt").write_text("Owned uncommitted source change. Never executed.\n")
    output = sweep(root, evidence, "dirty")
    assert output["data"]["report"]["head"]["sha"] == state["originalSha"]
    assert output["data"]["report"]["head"]["dirty"] is True
    assert all(row == {"kind": "source-unverified", "reason": "dirty-working-tree"}
        for row in verdicts(output).values())
    native(root, evidence, "dirty-skip-refused", "coverage:sweep", {"writeSkips": True}, False)
    state["stage"] = "dirty"
    save(evidence, "state", state)
    verify(root, evidence, "dirty")


def committed(root, evidence):
    state = load(evidence, "state")
    state["currentSha"] = commit(root, "Owned source metadata revision")
    assert state["currentSha"] != state["originalSha"]
    output = sweep(root, evidence, "committed")
    assert output["data"]["report"]["head"]["sha"] == state["currentSha"]
    assert output["data"]["report"]["head"]["dirty"] is False
    assert verdicts(output)[("root", "scan")] == {"kind": "changed", "files": 1}
    assert verdicts(output)[("root", "map")] == {"kind": "source-unverified", "reason": "dirty-baseline"}
    state["stage"] = "committed"
    save(evidence, "state", state)
    verify(root, evidence, "committed")


def no_work(root):
    database = root / ".kuzushi/v3/index.sqlite3"
    if database.is_file():
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
            tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            for table in ["finding_observations", "review_decisions", "investigation_call_reservations",
                    "investigation_work_attempts"]:
                if table in tables:
                    assert db.execute("select count(*) from " + table).fetchone()[0] == 0, table
    assert not (root / ".kuzushi/threat-model.json").exists()
    assert not (root / ".kuzushi/v3/campaigns").exists()


def verify(root, evidence, stage):
    state = load(evidence, "state")
    config = Path(state["home"]) / ".kuzushi/v3/config.toml"
    assert hashlib.sha256(config.read_bytes()).hexdigest() == state["configHash"]
    assert records(root) == [tuple(row) for row in state["records"]]
    expected = "Owned inert source metadata fixture. Never executed.\n"
    if state["stage"] != "prepared":
        expected = "Owned uncommitted source change. Never executed.\n"
    assert (root / "hello.txt").read_text() == expected
    assert git(root, "rev-parse", "HEAD") == state.get("currentSha", state["originalSha"])
    no_work(root)
    save(evidence, stage + "-check", {"historicalRows": 3, "historyUnchanged": True,
        "sourceBytesExpected": True, "configurationUnchanged": True, "historySynthetic": True,
        "providerRequests": 0, "scannerJobs": 0, "sourceExecuted": False,
        "findingObservations": 0, "reviewDecisions": 0, "providerReservations": 0, "workAttempts": 0})


root, evidence = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
action = sys.argv[3]
if action == "prepare":
    prepare(root, evidence, Path(sys.argv[4]).resolve())
elif action == "dirty":
    dirty(root, evidence)
elif action == "committed":
    committed(root, evidence)
else:
    verify(root, evidence, action)
