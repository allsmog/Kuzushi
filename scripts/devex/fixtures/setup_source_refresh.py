"""Owned Setup revision facts. No models, scanners or target-code execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def load(evidence):
    return json.loads((evidence / "state.json").read_text())


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


def native(root, evidence, stage, tool):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root),
        "run", tool, "--input", "{}"], capture_output=True, text=True, timeout=40)
    (evidence / (stage + ".stdout.json")).write_text(result.stdout)
    (evidence / (stage + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def prepare(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / ".gitignore").write_text("# Workspace maintains local state ignore rules.\n")
    (root / "hello.txt").write_text("Owned initial source. Never executed.\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    native(root, evidence, "initialization", "coverage:baselines")
    git(root, "init", "--quiet", "--initial-branch=main")
    sha = commit(root, "Owned initial source")
    save(evidence, "state", {"home": str(home), "originalSha": sha, "currentSha": sha,
        "branch": "main", "dirty": False, "stage": "prepared",
        "configHash": hashlib.sha256(config.read_bytes()).hexdigest()})
    verify(root, evidence, "prepared")


def committed(root, evidence):
    state = load(evidence)
    git(root, "checkout", "--quiet", "-b", "later")
    (root / "hello.txt").write_text("Owned later source. Never executed.\n")
    state.update(currentSha=commit(root, "Owned later source"), branch="later", stage="committed")
    assert state["currentSha"] != state["originalSha"]
    save(evidence, "state", state)
    output = native(root, evidence, "committed-sweep", "coverage:sweep")
    assert output["data"]["report"]["head"]["sha"] == state["currentSha"]
    assert output["data"]["report"]["head"]["dirty"] is False
    verify(root, evidence, "committed")


def dirty(root, evidence):
    state = load(evidence)
    (root / "hello.txt").write_text("Owned uncommitted source. Never executed.\n")
    state.update(dirty=True, stage="dirty")
    save(evidence, "state", state)
    output = native(root, evidence, "dirty-sweep", "coverage:sweep")
    assert output["data"]["report"]["head"]["sha"] == state["currentSha"]
    assert output["data"]["report"]["head"]["dirty"] is True
    verify(root, evidence, "dirty")


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
    state = load(evidence)
    config = Path(state["home"]) / ".kuzushi/v3/config.toml"
    assert hashlib.sha256(config.read_bytes()).hexdigest() == state["configHash"]
    expected = {"prepared": "Owned initial source. Never executed.\n",
        "committed": "Owned later source. Never executed.\n",
        "dirty": "Owned uncommitted source. Never executed.\n"}[state["stage"]]
    assert (root / "hello.txt").read_text() == expected
    assert git(root, "rev-parse", "HEAD") == state["currentSha"]
    assert git(root, "branch", "--show-current") == state["branch"]
    no_work(root)
    save(evidence, stage + "-check", {"sourceBytesExpected": True, "configurationUnchanged": True,
        "currentSha": state["currentSha"], "dirty": state["dirty"], "branch": state["branch"],
        "providerRequests": 0, "scannerJobs": 0, "sourceExecuted": False,
        "findingObservations": 0, "reviewDecisions": 0, "providerReservations": 0, "workAttempts": 0})


root, evidence = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
action = sys.argv[3]
if action == "prepare":
    prepare(root, evidence, Path(sys.argv[4]).resolve())
elif action == "committed":
    committed(root, evidence)
elif action == "dirty":
    dirty(root, evidence)
else:
    verify(root, evidence, action)
