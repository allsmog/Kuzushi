"""Inventory an isolated local source snapshot. Never execute its source."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from secret_settings import ledger
from inventory_input import owned_pane


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def environment(evidence, home):
    env = dict(os.environ, HOME=str(home), GIT_CONFIG_GLOBAL=str(evidence / "empty-git-config"),
               GIT_CONFIG_SYSTEM=str(evidence / "empty-git-config"))
    for key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "KUZUSHI_MODEL", "NODE_OPTIONS",
                "KUZUSHI_LANGGRAPH_BRIDGE"]:
        env.pop(key, None)
    return env


def git(root, evidence, home, *arguments, text=True, input=None):
    return subprocess.check_output(["git", *arguments], cwd=root,
        env=environment(evidence, home), text=text, input=input)


def source_files(root, evidence, home):
    names = git(root, evidence, home, "ls-files", "-z").rstrip("\0").split("\0")
    result = {}
    for name in names:
        path = root / name
        link = path.is_symlink()
        content = os.readlink(path).encode() if link else path.read_bytes()
        result[name] = {"kind": "symlink" if link else "file", "bytes": len(content),
                        "sha256": hashlib.sha256(content).hexdigest()}
    return result


def seed(root, evidence, home, repository):
    assert root.name == "fixture-target" and root.parent == evidence
    assert {path.name for path in root.iterdir()} == {".git", "app.py", "config.env"}, "Only replace the harness-owned seed"
    (evidence / "empty-git-config").write_text("")
    template = evidence / "empty-template"
    template.mkdir()
    expected = git(repository, evidence, home, "rev-parse", "HEAD").strip()
    assert git(repository, evidence, home, "branch", "--show-current").strip() == "main"
    shutil.rmtree(root)
    git(evidence, evidence, home, "-c", "core.hooksPath=/dev/null", "-c",
        "init.templateDir=" + str(template), "clone", "--depth=1", "--no-hardlinks",
        repository.as_uri(), str(root))
    assert git(root, evidence, home, "rev-parse", "HEAD").strip() == expected
    assert not (root / ".kuzushi").exists()
    source = source_files(root, evidence, home)
    assert len(source) > 5_000 and sum(row["bytes"] for row in source.values()) > 40_000_000
    assert sum(row["bytes"] > 262_144 for row in source.values()) > 0
    save(evidence, "source-before", source)
    save(evidence, "source-identity", {"gitRevision": expected,
        "gitTree": git(root, evidence, home, "rev-parse", "HEAD^{tree}").strip(),
        "trackedFiles": len(source), "trackedBytes": sum(row["bytes"] for row in source.values()),
        "sourceExecuted": False})


def native(root, evidence, home, name, inputs):
    started = time.monotonic()
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", "pack:scopes", "--input", json.dumps(inputs)], env=environment(evidence, home),
        capture_output=True, text=True, timeout=90)
    (evidence / (name + ".stdout.json")).write_text(result.stdout)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    save(evidence, name + "-timing", {"seconds": time.monotonic() - started})
    return json.loads(result.stdout)["data"]["review"]


def wait_for_result(root, tool, count, operation=None):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        selected = []
        for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
            value = json.loads(path.read_text())
            if value.get("tool") != tool:
                continue
            if operation and json.loads((path.parent / "input.json").read_text()).get("operation") != operation:
                continue
            selected.append(value)
        if len(selected) >= count and all(value["status"] != "running" for value in selected):
            return
        time.sleep(0.1)
    raise AssertionError("Expected a terminal receipt for " + tool)


def last_page(root, evidence):
    total = json.loads((evidence / "context-check.json").read_text())["inventoriedFiles"]
    offset = (total - 1) // 32 * 32
    expected = f"Files {offset + 1}..{total} of {total}"
    pane = owned_pane(root)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        screen = subprocess.check_output(["tmux", "capture-pane", "-p", "-t", pane], text=True)
        if expected in screen:
            save(evidence, "last-page-check", {"expected": expected, "pane": pane})
            return
        time.sleep(0.1)
    raise AssertionError("Last membership page never appeared: " + expected)


def verify_context(root, evidence):
    wait_for_result(root, "context:build", 1)
    snapshot = json.loads((root / ".kuzushi/context-snapshot.json").read_text())
    inventory = snapshot["repositoryInventory"]
    inspection = inventory["inspection"]
    source = json.loads((evidence / "source-before.json").read_text())
    assert inspection["entries"] == len(source)
    assert inspection["enumeration"] == "git-index" and inventory["truncation"]
    assert inspection["max_entries"] == 100_000
    assert inspection["max_inspected_bytes"] == 536_870_912
    assert inspection["max_file_inspection_bytes"] == 262_144
    assert inspection["inspected_bytes"] <= 536_870_912
    assert set(inspection["truncated_files"]) == {name for name, row in source.items() if row["bytes"] > 262_144}
    omitted = {row["path"] for row in inspection["omitted_paths"]}
    assert "CLAUDE.md" in omitted and "CLAUDE.md" not in inspection["files"]
    assert "Cargo.toml" in inspection["files"] and "package.json" in inspection["files"]
    assert len(snapshot["filesSample"]) == 200
    assert snapshot["filesIndexed"] == len(inspection["files"]) < len(source)
    save(evidence, "context-check", {"trackedFiles": len(source),
        "inventoriedFiles": len(inspection["files"]), "omittedPaths": inspection["omitted_paths"],
        "prefixLimitedFiles": inspection["truncated_files"], "inspectedBytes": inspection["inspected_bytes"],
        "partialReason": inventory["truncation"], "sampledFiles": len(snapshot["filesSample"])})


def verify(root, evidence, home, stage):
    if stage == "cached":
        wait_for_result(root, "pack:scopes", 2, "create")
    assert source_files(root, evidence, home) == json.loads((evidence / "source-before.json").read_text())
    assert not git(root, evidence, home, "status", "--porcelain", "--untracked-files=all", "--", ".", ":(exclude).kuzushi").strip()
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts", "finding_observations", "review_decisions"]:
            assert table not in tables or db.execute("select count(*) from " + table).fetchone()[0] == 0
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    review = native(root, evidence, home, stage, {"operation": "latest"})
    coverage = review["coverage"]
    inspection = json.loads((root / ".kuzushi/context-snapshot.json").read_text())["repositoryInventory"]["inspection"]
    limitations = "\n".join(coverage["limitations"])
    assert all("Omitted: " + row["path"] + ". Reason: " + row["reason"] in limitations for row in inspection["omitted_paths"])
    assert all("Prefix only: " + path in limitations for path in inspection["truncated_files"])
    assert coverage["inventoryLimited"] and not coverage["enumerationComplete"]
    assert coverage["uncoveredFiles"]["total"] == coverage["overlaps"]["total"] == 0
    assert review["identityOmissions"]["total"] == 0
    assert review["record"]["draft"]["scopes"][0]["paths"] == ["."]
    assert len(review["record"]["draft"]["scopes"]) == 1
    assert review["record"]["source"]["gitRevision"] == json.loads((evidence / "source-identity.json").read_text())["gitRevision"]
    if stage in ["draft", "cached", "refused"]:
        assert review["record"]["acceptance"] is None
    else:
        assert review["record"]["acceptance"] is not None
    if stage == "draft":
        save(evidence, "initial-scope", review)
    else:
        initial = json.loads((evidence / "initial-scope.json").read_text())
        assert review["record"]["inventoryHash"] == initial["record"]["inventoryHash"]
        if stage in ["cached", "refused"]:
            assert review["reference"] != initial["reference"]
    save(evidence, stage + "-check", {"reference": review["reference"], "coverage": coverage,
        "sourceBytesPreserved": True, "providerRequests": 0, "sourceExecuted": False, "jobsStarted": 0})
    return review


def advance_revision(root, evidence, home):
    before = git(root, evidence, home, "rev-parse", "HEAD").strip()
    tree = git(root, evidence, home, "rev-parse", "HEAD^{tree}").strip()
    after = git(root, evidence, home, "-c", "user.name=Owned fixture", "-c", "user.email=fixture@example.invalid",
        "commit-tree", tree, "-p", before, input="fixture: advance revision without source changes\n").strip()
    git(root, evidence, home, "update-ref", "refs/heads/main", after, before)
    assert git(root, evidence, home, "rev-parse", "HEAD^{tree}").strip() == tree
    save(evidence, "revision-change", {"before": before, "after": after, "sameGitTree": tree})


if __name__ == "__main__":
    root, evidence, home, repository = [Path(value).resolve() for value in sys.argv[1:5]]
    stage = sys.argv[5]
    if stage == "seed": seed(root, evidence, home, repository)
    elif stage == "context": verify_context(root, evidence)
    elif stage == "advance": advance_revision(root, evidence, home)
    elif stage == "last-page": last_page(root, evidence)
    else: verify(root, evidence, home, stage)
