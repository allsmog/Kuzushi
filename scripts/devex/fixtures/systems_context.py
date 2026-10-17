"""Owned source metadata for bounded context inspection. Never compiled or executed."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

TOOL = "systems-hunt:systems-context-gatherer"


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def sources(root):
    result = {}
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if name != ".kuzushi"
                           and not (Path(current) / name).is_symlink()]
        for name in files:
            path = Path(current) / name
            if not path.is_symlink():
                result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def seed(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    files = {"a loose root.c": "// Owned parser packet length shared guard metadata. Never executed.\n",
             "b services/owned Unicode café component/src/parser.rs":
                 "// Owned parser packet metadata.\n// guard length shared\n",
             "c large.c": "// Owned parser packet metadata.\n" * 1000,
             "d binary.c": "\0Owned parser metadata\n",
             "tests/parser_test.c": "// Owned test parser packet metadata.\n",
             "child/owned.rs": "// Owned child parser packet metadata.\n"}
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    (root / "cycle").symlink_to(root, target_is_directory=True)
    (evidence / "context-command.txt").write_text("run " + TOOL + " " + json.dumps(
        {"maxFiles": 2, "maxSourceBytes": 128, "headBytes": 96, "maxSurfaces": 1}))
    save(evidence, "expected-source", sources(root))


def results(root):
    found = []
    for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
        run = json.loads(path.read_text())
        output = path.with_name("result.json")
        if run.get("tool") == TOOL and output.exists():
            found.append((run, json.loads(output.read_text())))
    return sorted(found, key=lambda row: (row[0]["startedAtUnix"], row[0]["runId"]))


def counts(root, closed=False):
    path = root / ".kuzushi/v3/index.sqlite3"
    names = ["finding_observations", "review_decisions", "investigation_call_reservations",
             "investigation_work_attempts"]
    if not path.exists():
        return dict.fromkeys(names, 0)
    uri = path.as_uri() + "?mode=ro"
    if closed:
        # The child CLI has exited. Never ignore an unsettled WAL or journal.
        for suffix in ["-wal", "-journal"]:
            sidecar = path.with_name(path.name + suffix)
            assert not sidecar.exists() or sidecar.stat().st_size == 0, sidecar
        uri += "&immutable=1"
    with sqlite3.connect(uri, uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        return {name: db.execute("select count(*) from " + name).fetchone()[0]
                if name in tables else 0 for name in names}


def inspect(root, evidence, stage):
    assert sources(root) == json.loads((evidence / "expected-source.json").read_text())
    outputs = [output for _, output in results(root) if output.get("status") in ["partial", "completed"]]
    assert len(outputs) == (2 if stage == "restarted" else 1), len(outputs)
    output = outputs[-1]
    receipt = output["data"]["metadata"]["inspection"]
    assert output["status"] == "partial"
    assert "Further analysis requires a separate explicit action" in output["output"]
    assert receipt["completeRepositoryCoverage"] is False
    assert receipt["maxSourceFiles"] == 2 and receipt["maxSourceBytes"] == 128
    assert receipt["indexedFiles"] == 2 and receipt["omittedSourceFiles"] >= 3
    assert receipt["omittedSurfaces"] == 1
    assert receipt["codeIndex"] == receipt["codeqlInspection"] == "not_requested"
    assert output["data"]["surfaces"][0]["filePath"] == "a loose root.c"
    assert not (root / ".kuzushi/cpg-rs").exists()
    assert not (root / ".kuzushi/systems-hunt").exists()
    state = counts(root)
    assert all(value == 0 for value in state.values()), state
    save(evidence, stage + "-check", {"contextReceipts": len(outputs), "counts": state,
        "sourceAndHistoryUnchanged": True, "sourceExecuted": False, "providerRequests": 0,
        "receipt": receipt})


def cli(root, evidence, home):
    binary = os.environ["KUZUSHI_NATIVE_BIN"]
    env = {key: value for key, value in os.environ.items() if key not in [
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "KUZUSHI_MODEL", "NODE_OPTIONS", "KUZUSHI_AGENT_MCPS"]}
    env["HOME"] = str(home)
    args = [binary, "--target", str(root / "child"), "run", TOOL, "--input", "{}"]
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=60)
    save(evidence, "child-cli", {"exitCode": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["status"] == "completed", output
    assert output["data"]["surfaces"][0]["filePath"] == "owned.rs"
    assert output["data"]["metadata"]["inspection"]["indexedFiles"] == 1
    assert not (root / "child/.kuzushi/cpg-rs").exists()
    assert all(value == 0 for value in counts(root / "child", closed=True).values())
    check_prefix_fidelity(binary, env, evidence)


def check_prefix_fidelity(binary, env, evidence):
    fixture = evidence / "exact-source-fixture"
    fixture.mkdir()
    source = fixture / "owned.rs"
    checks = []
    for name, raw, limit, truncated, omitted, included, incomplete in [
        ("exact-limit", b"// parser\n", 10, 0, 0, 10, 0),
        ("utf8-boundary", "// parser 🙂 guard\n".encode(), 12, 1, 0, 10, 2),
        ("invalid-utf8", b"// parser \xff guard\n", 96, 0, 1, 0, 0),
    ]:
        source.write_bytes(raw)
        args = [binary, "--target", str(fixture), "run", TOOL, "--input", json.dumps(
            {"maxFiles": 1, "maxSourceBytes": limit, "headBytes": limit})]
        result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=60)
        output = json.loads(result.stdout)
        assert result.returncode == (4 if output["status"] == "partial" else 0), result.stderr
        receipt = output["data"]["metadata"]["inspection"]
        assert receipt["truncatedSourceFiles"] == truncated, (name, receipt)
        assert receipt["omittedSourceFiles"] == omitted, (name, receipt)
        assert receipt["includedSourceTextBytes"] == included, (name, receipt)
        assert receipt["incompleteUtf8PrefixBytes"] == incomplete, (name, receipt)
        assert receipt["inspectedSourceBytes"] == min(limit, len(raw))
        assert "�" not in json.dumps(output, ensure_ascii=False)
        assert source.read_bytes() == raw
        assert all(value == 0 for value in counts(fixture, closed=True).values())
        checks.append({"case": name, "exitCode": result.returncode, "receipt": receipt, "sourceUnchanged": True})
    save(evidence, "exact-prefix-cli", {"checks": checks, "providerRequests": 0})


root, evidence = map(Path, sys.argv[1:3])
stage = sys.argv[3]
if stage == "seed":
    seed(root, evidence)
elif stage == "cli":
    cli(root, evidence, Path(sys.argv[4]))
else:
    inspect(root, evidence, stage)
    if stage == "reader":
        text = "\n".join(path.read_text() for path in evidence.glob("*-context-reading-*.txt"))
        for token in ["Coverage:", "Omitted:", "a loose root.c"]:
            assert token in text, token
        save(evidence, "reader-content-check", {"coverageAndOmissionsReachableAt40Columns": True})
