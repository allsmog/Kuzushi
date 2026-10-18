"""Owned content-prefix inventory. No model requests or source execution."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from secret_settings import ledger


def hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["root.rs", "large.rs"]}


def seed(root, evidence, home):
    assert root.name == "fixture-target" and root.parent == evidence
    assert {p.name for p in root.iterdir()} <= {".git", "app.py", "config.env"}
    repository = root / ".git"
    if repository.exists():
        assert repository.is_dir() and not repository.is_symlink()
        shutil.rmtree(repository)
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "root.rs").write_text("// Owned inert root source.\n")
    (root / "large.rs").write_bytes(b"// Owned inert inventory prefix.\n" * 9000)
    (evidence / "source-before.json").write_text(json.dumps(hashes(root)) + "\n")
    (evidence / "runtime-home.txt").write_text(str(home))
    (evidence / "empty-git-config").write_text("")


def latest(root, evidence, stage):
    command = [os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
               "run", "pack:scopes", "--input", '{"operation":"latest"}']
    environment = dict(os.environ, HOME=(evidence / "runtime-home.txt").read_text(),
                       GIT_CONFIG_GLOBAL=str(evidence / "empty-git-config"),
                       GIT_CONFIG_SYSTEM=str(evidence / "empty-git-config"))
    for key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "NODE_OPTIONS",
                "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE"]:
        environment.pop(key, None)
    result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=30)
    (evidence / (stage + "-read.json")).write_text(result.stdout)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["data"]["review"]


def verify(root, evidence, stage):
    review = latest(root, evidence, stage)
    coverage = review["coverage"]
    assert coverage["enumerationComplete"] is True
    assert coverage["inventoryLimited"] is True
    assert coverage["enumeratedFiles"] == 2
    assert coverage["uncoveredFiles"]["total"] == 0
    assert review["identityOmissions"]["total"] == 0
    assert review["record"]["draft"]["scopes"][0]["paths"] == ["."]
    accepted = stage in ["accepted", "restarted"]
    assert (review["record"]["acceptance"] is not None) == accepted
    if accepted:
        assert review["record"]["acceptance"]["inventoryLimitations"]
    inventory = root / ".kuzushi/v3/scan-scopes/inventories" / (review["record"]["inventoryHash"] + ".json")
    inspection = json.loads(inventory.read_text())["inspection"]
    assert inspection["enumeration_complete"] is True
    assert inspection["truncated_files"] == ["large.rs"]
    assert inspection["max_entries"] == 100000
    assert inspection["max_inspected_bytes"] == 512 * 1024 * 1024
    assert inspection["max_file_inspection_bytes"] == 256 * 1024
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    assert not (root / ".kuzushi/v3/campaigns").exists()
    counts = recorded_counts(root, evidence)
    assert all(value in [None, 0] for value in counts.values()), counts
    tools = {json.loads(path.read_text()).get("tool")
             for path in (root / ".kuzushi/v3/runs").glob("*/run.json")}
    assert tools == {"pack:scopes"}, tools
    (evidence / (stage + "-verified.json")).write_text(json.dumps({
        "stage": stage, "reference": review["reference"], "enumerationComplete": True,
        "inventoryLimited": True, "files": 2, "accepted": accepted, "ledgerCounts": counts,
        "allowanceStorage": "not_initialized" if all(value is None for key, value in counts.items()
            if key.startswith("investigation_")) else "initialized_empty",
        "recordedTools": sorted(tools),
        "sourceUnchanged": True, "modelRequests": 0, "sourceExecuted": False}, indent=2) + "\n")


def recorded_counts(root, evidence):
    names = ["finding_observations", "review_decisions", "investigation_allowance_revisions",
             "investigation_call_reservations", "investigation_work_attempts"]
    counts = dict.fromkeys(names)
    database = root / ".kuzushi/v3/index.sqlite3"
    if not database.is_file():
        return counts
    with ledger(root, evidence) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for name in names:
            if name in tables:
                counts[name] = connection.execute("select count(*) from " + name).fetchone()[0]
    return counts


if __name__ == "__main__":
    stage, target, output = sys.argv[1:4]
    root, evidence = Path(target).resolve(), Path(output).resolve()
    assert root.name == "fixture-target" and root.parent == evidence
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, stage)
