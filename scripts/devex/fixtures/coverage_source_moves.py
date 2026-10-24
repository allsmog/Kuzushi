"""Owned source moves across real Git revisions, without scanning or executing source."""
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path

import source_baselines as base


def commit(root, message):
    base.git(root, "add", "-A")
    base.git(root, "-c", "user.name=Owned fixture", "-c", "user.email=fixture@example.test",
             "-c", "commit.gpgsign=false", "commit", "-m", message)
    return base.git(root, "rev-parse", "HEAD")


def source_hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in [".gitignore", "docs/moved.txt", "stable/notice.txt"]}


def prepare(root, evidence, home):
    assert root.name == "fixture-target" and root.parent == evidence
    base.prepare(root, evidence, home)
    # Isolate global settings from the enclosing repository's artifact ignore policy.
    base.git(home, "init", "--quiet", "--initial-branch=main")
    for name in ["src", "docs", "stable"]:
        (root / name).mkdir()
    base.git(root, "mv", "hello.txt", "src/original.txt")
    (root / "stable/notice.txt").write_text("Owned inert unchanged text. Never executed.\n")
    original = commit(root, "Owned boundary baseline")
    scopes = [("root", "."), ("departed", "src"), ("arrived", "docs"), ("untouched", "stable")]
    tree = {"schemaVersion": 2, "root": "root", "scopes": [
        {"id": name, "parent": None if name == "root" else "root",
         "kind": "root" if name == "root" else "package-root", "relPath": path,
         "inheritedSections": []} for name, path in scopes]}
    folder = root / ".kuzushi/v3/project-model"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "scopes.json").write_text(json.dumps(tree) + "\n")
    with sqlite3.connect(root / ".kuzushi/v3/coverage.sqlite3") as database:
        database.execute("delete from scan_baselines")
        database.executemany("insert into scan_baselines values (?,?,?,?,?,?,?,?)", [
            (name, "scan", "synthetic-history", "synthetic-not-a-scan", original, "main", 0, 100)
            for name, _ in scopes])
    before = base.records(root)
    base.git(root, "mv", "src/original.txt", "docs/moved.txt")
    current = commit(root, "Owned move across boundaries")
    base.git(root, "config", "diff.renames", "copies")
    base.save(evidence, "move-state", {"originalSha": original, "currentSha": current,
              "before": before, "sourceHashes": source_hashes(root)})


def verify(root, evidence, stage):
    state = base.load(evidence, "move-state")
    assert state["originalSha"] != state["currentSha"]
    assert base.git(root, "rev-parse", "HEAD") == state["currentSha"]
    assert not (root / "src/original.txt").exists()
    assert source_hashes(root) == state["sourceHashes"]
    output = base.sweep(root, evidence, stage)
    expected = {(name, "scan"): {"kind": "changed", "files": count}
                for name, count in [("root", 2), ("departed", 1), ("arrived", 1)]}
    expected[("untouched", "scan")] = {"kind": "current"}
    assert base.verdicts(output) == expected, base.verdicts(output)
    rows = [list(row) for row in base.records(root)]
    originals = [row for row in rows if row[2] == "synthetic-history"]
    skips = [row for row in rows if row[2] == "sweep-skip"]
    assert originals == state["before"] and len(skips) == 1
    assert skips[0][0:2] == ["untouched", "scan"]
    assert skips[0][4] == state["currentSha"] and skips[0][6] == 0
    advice = base.native(root, evidence, stage + "-recommend", "coverage:recommend", {"compareSource": True})
    changed = {row["scopeId"] for row in advice["data"]["recommendations"] if row["reason"] == "changed"}
    assert changed == {"root", "departed", "arrived"}, changed
    assert advice["data"]["sourceFreshnessVerified"] is False
    base.no_work(root)
    base.save(evidence, stage + "-move-proof", {"sourceUnchanged": True, "historySynthetic": True,
              "originalSha": state["originalSha"], "currentSha": state["currentSha"],
              "changedScopes": sorted(changed), "skipScope": "untouched", "historicalRows": len(rows),
              "providerRequests": 0, "sourceExecuted": False})


def compact_reader(evidence):
    covered, totals = set(), set()
    captures = 0
    for path in evidence.glob("*.txt"):
        provenance = path.with_suffix(".provenance.json")
        if not provenance.is_file():
            continue
        dimensions = json.loads(provenance.read_text())["actual_dimensions"]
        if dimensions != {"width": 40, "height": 12}:
            continue
        match = re.search(r"rows (\d+)[–-](\d+)/(\d+)", path.read_text())
        assert match, path
        start, end, total = map(int, match.groups())
        covered.update(range(start, end + 1))
        totals.add(total)
        captures += 1
    assert len(totals) == 1, totals
    total = totals.pop()
    assert covered == set(range(1, total + 1)), sorted(set(range(1, total + 1)) - covered)
    base.save(evidence, "compact-reader-proof", {"allTranscriptRowsReached": True,
              "virtualRows": total, "capturePairs": captures, "width": 40, "height": 12})


if __name__ == "__main__":
    target, artifacts, runtime_home = [Path(value).resolve() for value in sys.argv[1:4]]
    action = sys.argv[4]
    if action == "prepare":
        prepare(target, artifacts, runtime_home)
    elif action == "compact":
        compact_reader(artifacts)
    else:
        assert action in ["checked", "restarted"]
        verify(target, artifacts, action)
