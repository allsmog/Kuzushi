"""Owned pre-existing inert Git source plus a fake CodeQL launcher. No target code runs."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

TOOLS = {"create": "codeql:create-db", "scan": "codeql:scan"}


def git(root, *arguments):
    return subprocess.check_output(["git", "-C", str(root), *arguments], text=True).strip()


def sources(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in git(root, "ls-files").splitlines()}


def seed(root, evidence):
    assert root == evidence / "fixture-target"
    source = Path(os.environ["KUZUSHI_CODEQL_OWNED_SOURCE"]).resolve()
    assert (source / ".git").is_dir()
    shutil.rmtree(root)
    subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", str(source), str(root)], check=True)
    assert not git(root, "status", "--porcelain")
    (evidence / "source-before.json").write_text(json.dumps({"sha": git(root, "rev-parse", "HEAD"), "files": sources(root)}))
    bundle = evidence / "owned-bundle"
    bundle.mkdir(exist_ok=True)
    binary = bundle / "codeql"
    binary.write_text(r'''#!/bin/sh
if [ "$1" = 'database' ] && [ "$2" = 'create' ]; then
  out="$3"
  mkdir -p "$out/db-rust"
  printf 'primaryLanguage: rust\n' > "$out/codeql-database.yml"
  printf 'Owned inert database bytes' > "$out/db-rust/owned.data"
  exit 0
fi
if [ "$1" = 'database' ] && [ "$2" = 'analyze' ]; then
  for arg in "$@"; do case "$arg" in --output=*) out="${arg#--output=}" ;; esac; done
  printf '%s' '{"runs":[{"tool":{"driver":{"rules":[{"id":"owned/source-observation","properties":{"problem":{"severity":"warning"}}}]}},"results":[{"ruleId":"owned/source-observation","message":{"text":"Labeled owned source observation. No defect is claimed."},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.rs"},"region":{"startLine":1}}}]}]}]}' > "$out"
  exit 0
fi
printf 'Unexpected owned stub request' >&2
exit 2
''')
    binary.chmod(0o700)
    values = {
        "create": {"language": "rust", "buildMode": "none", "codeqlBin": str(binary), "timeoutMs": 2000},
        "scan": {"language": "rust", "binary": str(binary), "dbPath": ".kuzushi/v3/codeql-db", "threads": 1, "timeoutMs": 2000},
    }
    for name, value in values.items():
        (evidence / (name + ".txt")).write_text("run " + TOOLS[name] + " " + json.dumps(value))
    raw = root / ".kuzushi/raw-db"
    raw.mkdir(parents=True)
    (raw / "codeql-database.yml").write_text("primaryLanguage: rust\n")
    (raw / "db-rust").mkdir()
    (evidence / "raw.txt").write_text("run codeql:scan " + json.dumps(dict(values["scan"], dbPath=str(raw))))


def result_for(root, tool, status):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        rows = [(p.parent, json.loads(p.read_text())) for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
        rows = [(p, r) for p, r in rows if r.get("tool") == tool and r.get("status") == status]
        if len(rows) == 1:
            path, run = rows[0]
            assert not run.get("phase")
            return path, run, json.loads((path / "result.json").read_text())
        time.sleep(.05)
    raise AssertionError(rows)


def verify(root, evidence, stage):
    original = json.loads((evidence / "source-before.json").read_text())
    assert git(root, "rev-parse", "HEAD") == original["sha"]
    if stage not in ["dirty", "refused", "restart"]:
        assert sources(root) == original["files"]
    create_path, create_run, created = result_for(root, TOOLS["create"], "completed")
    assert created["data"]["sourceCommit"] == original["sha"]
    assert created["data"]["targetScope"] == "."
    (evidence / "create-replay.txt").write_text("replay " + create_run["runId"])
    if stage == "create":
        return
    path, run, result = result_for(root, TOOLS["scan"], "partial")
    assert result["status"] == "partial" and result["data"]["count"] == 1
    assert result["data"]["findings"][0]["file_path"] == "main.rs"
    assert any("independent review" in row for row in result["data"]["scanErrors"])
    (evidence / "scan-replay.txt").write_text("replay " + run["runId"])
    digest = hashlib.sha256((path / "result.json").read_bytes()).hexdigest()
    saved = evidence / "result.sha256"
    if saved.exists():
        assert saved.read_text() == digest
    else:
        saved.write_text(digest)
    if stage == "dirty":
        with (root / "main.rs").open("a") as out:
            out.write("// Owned uncommitted annotation. Never executed.\n")
    if stage in ["refused", "restart"]:
        rows = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/runs").glob("*/result.json")]
        assert any(row.get("status") == "failed" and "clean" in json.dumps(row) for row in rows)
    (evidence / (stage + "-check.json")).write_text(json.dumps({"newGitCommits": 0, "sourceExecution": False,
        "providerCalls": 0, "realCodeqlCalls": 0, "sourceCommit": original["sha"],
        "observationsAreSynthetic": True, "phaseContinuation": False}, indent=2) + "\n")


if __name__ == "__main__":
    stage, root, evidence = sys.argv[1:]
    root, evidence = Path(root).resolve(), Path(evidence).resolve()
    if stage == "seed":
        seed(root, evidence)
    else:
        verify(root, evidence, stage)
