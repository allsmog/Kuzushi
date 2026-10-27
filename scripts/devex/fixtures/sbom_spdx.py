"""Owned SPDX identity, incomplete graph and unchanged-source checks."""
import hashlib
import json
import re
import sys
from pathlib import Path

from sbom_shapes import assert_no_investigation

NAMES = ["package.json", "sub/package.json", "pnpm-lock.yaml", "README.md"]
LOCK = """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      library:
        specifier: ^1.0
        version: 1.0.0
packages:
  library@1.0.0: {}
  library@2.0.0: {}
  other@1.0.0: {}
snapshots:
  library@1.0.0:
    dependencies:
      other: 1.0.0
      missing: 0.0.0
  library@2.0.0:
    dependencies:
      other: 1.0.0
"""


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def sources(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in NAMES}


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "sub").mkdir(exist_ok=True)
    (root / "package.json").write_text(json.dumps({
        "name": "owned-export", "dependencies": {"library": "^1.0"},
        "scripts": {"postinstall": "touch must-not-execute"}}) + "\n")
    (root / "sub/package.json").write_text('{"dependencies":{"library":"^3.0"}}\n')
    (root / "pnpm-lock.yaml").write_text(LOCK)
    (root / "README.md").write_text("Owned inert export metadata. No installation.\n")
    save(evidence, "source", sources(root))


def inspect(root, evidence, stage):
    assert sources(root) == json.loads((evidence / "source.json").read_text())
    assert_no_investigation(root)
    results = {p.parent.name: json.loads(p.read_text())
               for p in (root / ".kuzushi/v3/runs").glob("*/result.json")}
    assert len(results) == 1, results
    result = next(iter(results.values()))
    assert result["status"] == "completed", result
    data = result["data"]
    assert data["componentCount"] == 5 and data["dependencyCount"] == 5, data
    assert data["inspection"]["capturedFiles"] == 3
    document = data["spdx"]
    ids = {p["SPDXID"] for p in document["packages"]}
    assert len(ids) == len(document["packages"]) == 5
    known = ids | {"SPDXRef-DOCUMENT"}
    relationships = document["relationships"]
    assert all(r["spdxElementId"] in known and r["relatedSpdxElement"] in known
               for r in relationships)
    assert sum(r["relationshipType"] == "DESCRIBES" for r in relationships) == 5
    assert sum(r["relationshipType"] == "DEPENDS_ON" for r in relationships) == 2
    diagnostics = data["spdxExport"]
    assert diagnostics["omittedRelationshipCount"] == 3
    assert diagnostics["dependencyRelationshipCount"] == 2
    omissions = {(r["source"], r["from"], r["to"])
                 for r in diagnostics["omittedRelationships"]}
    assert omissions == {("pnpm-lock.yaml", "root", "library"),
                         ("pnpm-lock.yaml", "library", "other"),
                         ("pnpm-lock.yaml", "library", "missing")}, omissions
    assert "SPDX and CycloneDX omitted 3 dependency relationships" in result["output"]
    assert sum(a["comment"].startswith("omittedDependency=")
               for a in document["annotations"]) == 3
    if stage == "restarted":
        assert sorted(results) == json.loads((evidence / "initial-check.json").read_text())["runs"]
    save(evidence, stage + "-check", {"runs": sorted(results), "packages": 5,
         "uniqueIds": 5, "rawDependencyLinks": 5, "exportedDependencyLinks": 2,
         "disclosedOmissions": 3, "sourceUnchanged": True, "modelRequests": 0,
         "targetExecuted": False, "fullConformanceQualified": False})


def inspect_warning_pages(evidence):
    captures = sorted(evidence.glob("*warning-40x12.txt"))
    captures += sorted(evidence.glob("*warning-expanded-40x12.txt"))
    captures += sorted(evidence.glob("*warning-page-*-40x12.txt"))
    phrases = ["SPDX and CycloneDX omitted 3 dependency relationships", "missing or ambiguous endpoints",
               "raw dependency links remain available"]
    complete = []
    for path in captures:
        rows = []
        for line in path.read_text().splitlines():
            row = line.strip(" │")
            row = re.sub(r"^\d{2}:\d{2}:\d{2}Z\s+\S+\s*", "", row)
            rows.append(re.sub(r"^…\s*", "", row))
        text = " ".join(" ".join(rows).split())
        if all(phrase in text for phrase in phrases):
            complete.append(path.name)
    assert complete, "No captured viewport contains the full omission warning"
    save(evidence, "warning-pages-check", {"captures": [p.name for p in captures],
         "completeWarningViewports": complete, "completeOmissionWarningReachable": True,
         "formalOperatorAcceptance": False})


if __name__ == "__main__":
    root, evidence = [Path(x).resolve() for x in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence)
    elif stage == "warning-pages":
        inspect_warning_pages(evidence)
    else:
        inspect(root, evidence, stage)
