"""Actual source parsing and graph artifacts. Target source is never executed."""
import hashlib
import json
import os
import sys
import subprocess
from pathlib import Path

from secret_settings import ledger


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def native(root, evidence, name, args, codes=(0,)):
    env = dict(os.environ, HOME=str(evidence / "home"))
    for key in ["NODE_OPTIONS", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
        env.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root), *args],
        env=env, capture_output=True, text=True, timeout=45)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    (evidence / (name + ".stdout.txt")).write_text(result.stdout)
    save(evidence, name + "-process", {"exitCode":result.returncode, "structuredOutput":bool(result.stdout.strip())})
    assert result.returncode in codes, result.stderr
    if not result.stdout.strip():
        assert result.returncode != 0
        return None
    receipt = json.loads(result.stdout)
    save(evidence, name, receipt)
    return receipt


def tool(root, evidence, name, value, codes=(0,)):
    return native(root, evidence, name, ["run", "cpg:build", "--input", json.dumps(value)], codes)


def sources(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [root / "first/greeting.go", root / "second/greeting.go", root / "invalid.py"]}


def seed(root, evidence, home):
    evidence.mkdir(parents=True, exist_ok=True)
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    for name in ["first", "second"]:
        (root / name).mkdir(parents=True, exist_ok=True)
        (root / name / "greeting.go").write_text("package greeting\nfunc Greeting() string { return \"Hello\" }\n")
    (root / "invalid.py").write_bytes(bytes([255]))
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    assert home == (evidence / "home").resolve()
    save(evidence, "source-before", sources(root))
    catalogs = [native(root, evidence, "catalog-all", ["tools", "--all", "--json"]),
                native(root, evidence, "catalog-default", ["tools", "--json"])]
    cpg = next(row for row in catalogs[0] if row["name"] == "cpg:build")
    assert cpg["maturity"] == "labs" and cpg["phase"] == "map"
    assert all(row["name"] != "cpg:build" for row in catalogs[1])
    receipt = tool(root, evidence, "scoped", {"languages":"go","subdir":"first","maxSourceFiles":2})
    graph = receipt["data"]["graphs"][0]
    assert graph["sourceFiles"] == 1 and graph["methods"] > 0 and Path(graph["cpgPath"]).is_file()
    assert Path(graph["cpgPath"]).is_relative_to(root / ".kuzushi/cpg-rs/scoped")
    for label, value in [("unsupported-scope", {"scanScopeRef":{}}),
        ("unsupported-language", {"languages":"kotlin"}), ("outside", {"subdir":"../outside"})]:
        failure = tool(root, evidence, label, value, (2, 3))
        assert failure is None or failure["status"] in ["failed", "blocked"]
    verify(root, evidence, "prepared")


def changed(root, evidence):
    assert sources(root) == json.loads((evidence / "source-before.json").read_text())
    with (root / "first/greeting.go").open("a") as output:
        output.write("// Owned source revision for cache refusal. Never executed.\n")
    save(evidence, "source-changed", sources(root))


def verify(root, evidence, stage):
    expected = "source-changed" if (evidence / "source-changed.json").exists() else "source-before"
    assert sources(root) == json.loads((evidence / (expected + ".json")).read_text())
    rows = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/runs").glob("*/result.json")]
    partial = [row for row in rows if row["status"] == "partial" and row.get("data", {}).get("graphs")]
    if stage != "prepared":
        assert partial and partial[-1]["data"]["graphs"][0]["language"] == "go"
        assert "python" in partial[-1]["data"]["stopReason"]
        assert Path(partial[-1]["data"]["graphs"][0]["cpgPath"]).is_file()
    counts = {table: 0 for table in ["investigation_call_reservations", "investigation_work_attempts", "finding_observations", "review_decisions"]}
    if (root / ".kuzushi/v3/index.sqlite3").exists():
        with ledger(root, evidence) as db:
            tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            counts = {table: db.execute("select count(*) from " + table).fetchone()[0] if table in tables else None for table in counts}
    assert all(count in [None, 0] for count in counts.values())
    phase_path = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    assert not phase_path.exists() or not phase_path.read_text().strip()
    save(evidence, stage + "-verified", {"sourceMatchesPlannedStage":True, "counts":counts,
         "acceptedMapCreated":False, "targetSourceExecuted":False})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "changed":
        changed(root, evidence)
    else:
        verify(root, evidence, stage)
