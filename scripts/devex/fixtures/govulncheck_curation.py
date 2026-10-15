"""Owned inert Go metadata. Catalog inspection only, no scanner or model."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from secret_settings import ledger


def save(folder, name, value):
    (folder / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source_hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["README.md", "go.mod"]}


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "README.md").write_text("# Owned metadata fixture\nNo Go package is loaded or executed.\n")
    (root / "go.mod").write_text("module owned.invalid/metadata\n\ngo 1.23\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("")
    (evidence / "home.txt").write_text(str(home))
    save(evidence, "source-before", source_hashes(root))


def catalog(root, evidence):
    env = dict(os.environ, HOME=(evidence / "home.txt").read_text())
    for label, args in [("default", ["tools", "--json"]), ("all", ["tools", "--all", "--json"])]:
        result = subprocess.run([env["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root), *args],
                                env=env, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        tools = json.loads(result.stdout)
        save(evidence, label + "-catalog", tools)
        matches = [tool for tool in tools if tool["name"] == "govulncheck:scan"]
        if label == "default":
            assert not matches
        else:
            assert len(matches) == 1 and matches[0]["maturity"] == "labs"
            assert "runtime reachability is not established" in matches[0]["description"]
            assert matches[0].get("runtime_requirement", "never") == "never"
    verify(root, evidence)


def verify(root, evidence):
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    names = ["finding_observations", "investigation_call_reservations", "investigation_work_attempts", "review_decisions"]
    counts = dict.fromkeys(names, 0)
    if (root / ".kuzushi/v3/index.sqlite3").is_file():
        with ledger(root, evidence) as database:
            tables = {row[0] for row in database.execute("select name from sqlite_master where type='table'")}
            counts = {name: database.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0 for name in names}
    assert all(value == 0 for value in counts.values()), counts
    assert not list((root / ".kuzushi/v3/runs").glob("*/run.json"))
    save(evidence, "verified", {"counts":counts, "sourceUnchanged":True, "scannerInvoked":False,
                              "modelCalls":0, "sourceExecuted":False, "coreDefault":False})


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed": seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "catalog": catalog(root, evidence)
    else: verify(root, evidence)
