"""Owned pnpm snapshot graph, failure and Components recovery evidence."""
import hashlib
import json
import sys
from pathlib import Path

from sbom_shapes import assert_no_investigation

LOCK = """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      outer:
        specifier: ^1.0.0
        version: 1.0.0(peer@2.0.0)
packages:
  outer@1.0.0: {}
  inner@2.0.0: {}
  '@scope/plugin@3.0.0': {}
  optional@4.0.0: {}
snapshots:
  outer@1.0.0(peer@2.0.0):
    dependencies:
      inner: 2.0.0
    optionalDependencies:
      optional: 4.0.0
    transitivePeerDependencies:
      - peer
  '@scope/plugin@3.0.0(@scope/peer@5.0.0)':
    dependencies:
      outer: 1.0.0(peer@2.0.0)
"""
NAMES = ["package.json", "pnpm-lock.yaml", "README.md"]


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def sources(root):
    return {n: hashlib.sha256((root / n).read_bytes()).hexdigest() for n in NAMES}


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "package.json").write_text(json.dumps({
        "name": "owned-pnpm-inventory", "private": True,
        "dependencies": {"outer": "^1.0.0"},
        "scripts": {"postinstall": "touch must-not-execute"}}) + "\n")
    (root / "pnpm-lock.yaml").write_text(LOCK)
    (root / "README.md").write_text("Owned inert dependency metadata. No installation or execution.\n")
    save(evidence, "valid-source", sources(root))


def edit(root, evidence, broken):
    expected = "valid-source" if broken else "broken-source"
    assert sources(root) == json.loads((evidence / (expected + ".json")).read_text())
    lock = LOCK.replace("inner: 2.0.0", "inner: 2") if broken else LOCK
    (root / "pnpm-lock.yaml").write_text(lock)
    save(evidence, "broken-source" if broken else "valid-source", sources(root))


def assert_graph(row):
    data = row["data"]
    assert data["componentCount"] == 5, data
    edges = {(x["source"], x["from"], x["to"]) for x in data["dependencies"]}
    expected = {("package.json", "root", "outer"),
                ("pnpm-lock.yaml", "root", "outer"),
                ("pnpm-lock.yaml", "outer", "inner"),
                ("pnpm-lock.yaml", "outer", "optional"),
                ("pnpm-lock.yaml", "@scope/plugin", "outer")}
    assert edges == expected, edges
    assert data["dependencyCount"] == 5, data
    assert data["inspection"]["capturedFiles"] == 2, data
    assert {x["name"] for x in data["components"]} == {"outer", "inner", "optional", "@scope/plugin"}
    assert all("(" not in x["name"] for x in data["components"])
    assert sum(x["relationshipType"] == "DEPENDS_ON"
               for x in data["spdx"]["relationships"]) == 5


def inspect(root, evidence, stage):
    expected = "broken-source" if stage == "failed" else "valid-source"
    assert sources(root) == json.loads((evidence / (expected + ".json")).read_text())
    assert_no_investigation(root)
    receipts = {p.parent.name: json.loads(p.read_text())
                for p in (root / ".kuzushi/v3/runs").glob("*/result.json")}
    completed = {k: v for k, v in receipts.items() if v.get("status") == "completed"}
    failed = {k: v for k, v in receipts.items() if v.get("status") == "failed"}
    assert len(completed) == (2 if stage in ["corrected", "restarted"] else 1), receipts
    assert len(failed) == (0 if stage == "initial" else 1), receipts
    for row in completed.values():
        assert_graph(row)
    for row in failed.values():
        assert "pnpm-lock.yaml" in json.dumps(row)
        assert "snapshot dependency versions must be strings" in json.dumps(row)
        for key in ["components", "dependencies", "spdx", "cycloneDx"]:
            assert key not in row["data"], row
        assert row["data"]["inspection"]["capturedFiles"] == 2
    if stage == "restarted":
        assert sorted(receipts) == json.loads((evidence / "corrected-check.json").read_text())["runs"]
    save(evidence, stage + "-check", {"runs": sorted(receipts), "completed": len(completed),
         "failed": len(failed), "sourceUnchanged": True, "modelRequests": 0,
         "targetExecution": False, "dependencyLinksPerSuccess": 5,
         "spdxIdUniquenessQualified": False})


def inspect_failure_pages(evidence):
    captures = sorted(evidence.glob("*failed-40x12.txt"))
    captures += sorted(evidence.glob("*failure-page-*-40x12.txt"))
    assert len(captures) == 3, captures
    text = " ".join(" ".join(p.read_text().split()) for p in captures)
    for expected in ["pnpm-lock.yaml", "snapshot dependency versions must be strings",
                     "options sbom-scan:scan", "Check the reported file or limit"]:
        assert expected in text, (expected, text)
    save(evidence, "failure-pages", {"captures": [p.name for p in captures],
                                   "completeCauseAndRecoveryReachable": True})


if __name__ == "__main__":
    root, evidence = [Path(x).resolve() for x in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence)
    elif stage in ["break", "correct"]:
        edit(root, evidence, stage == "break")
    elif stage == "failure-pages":
        inspect_failure_pages(evidence)
    else:
        inspect(root, evidence, stage)
