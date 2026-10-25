"""Owned literal-path navigation. No inference or target-source execution."""
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path

from rejected_context import execute


PATHS = [r"src/a\b.rs", "src/a/b.rs"]


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def graph():
    return {
        "version": "1", "methodology": "stride", "summary": {}, "threats": [],
        "title": "Labeled literal-path diagram",
        "systemContext": "Two inert source files provide distinct navigation evidence. The topology is declared fixture data, not verified deployment architecture.",
        "dfd": {
            "nodes": [
                {"id": "literal", "name": "Literal file", "type": "process",
                 "trustZone": "outer", "sourceRefs": [PATHS[0] + ":1"]},
                {"id": "nested", "name": "Nested file", "type": "process",
                 "trustZone": "inner", "sourceRefs": [PATHS[1] + ":1"]},
            ],
            "flows": [{"id": "link", "description": "Declared fixture link",
                       "sourceId": "literal", "targetId": "nested",
                       "sourceRefs": [PATHS[0] + ":1"], "trustBoundaryIds": ["edge"]}],
            "trustBoundaries": [{"id": "edge", "name": "Declared fixture boundary",
                                 "outerZone": "outer", "innerZone": "inner",
                                 "crossingFlowIds": ["link"], "sourceRefs": [PATHS[1] + ":1"]}],
        },
        "attackSurface": {"entryPoints": [], "roleGates": [], "externalSinks": [], "trustedCallers": []},
    }


def facts(root):
    database = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(database.as_uri() + "?mode=rw", uri=True) as db:
        db.execute("pragma query_only=on")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0]
                  for name in tables if name.startswith("investigation_")
                  or name in ["finding_observations", "review_decisions"]}
        counts = {name: count for name, count in counts.items()
                  if count or not name.startswith("investigation_")}
    hashes = {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in PATHS}
    manifest = root / ".kuzushi/threat-models/manifest.json"
    return {"counts": counts, "sources": hashes,
            "context": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "results": {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in (root / ".kuzushi/v3/runs").glob("*/result.json")}}


def seed(root, evidence, home):
    assert sys.platform != "win32", "This regression requires literal Unix backslashes"
    for name in ["main.rs", "app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "src/a").mkdir(parents=True, exist_ok=True)
    for index, path in enumerate(PATHS):
        (root / path).write_text("// Owned inert evidence. Never executed.\n")
        incoming = evidence / ("observation-" + str(index) + ".jsonl")
        incoming.write_text(json.dumps({"file": path, "line": 1, "severity": "info",
            "class": "literal" if index == 0 else "nested",
            "title": "Labeled literal-file observation" if index == 0 else "Labeled nested-file observation",
            "message": "Synthetic navigation fixture; no security defect is claimed."}) + "\n")
        execute(root, home, evidence, "import-" + str(index), "workspace:import-findings",
                {"path": str(incoming), "tool": "owned-links"})
    execute(root, home, evidence, "diagram", "threat-model:import",
            {"document": graph(), "label": "Owned literal paths", "activate": True})
    for index, path in enumerate(PATHS):
        rows = execute(root, home, evidence, "exact-query-" + str(index), "findings:list",
                       {"filePaths": [path]})["findings"]
        assert len(rows) == 1, rows
        assert rows[0].get("filePath", rows[0].get("file_path")) == path, rows
    before = facts(root)
    assert before["counts"]["finding_observations"] == 2
    assert before["counts"]["review_decisions"] == 0
    assert not any(name.startswith("investigation_") for name in before["counts"])
    save(evidence, "before", before)


def verify(root, evidence, stage):
    assert facts(root) == json.loads((evidence / "before.json").read_text())
    assert not (root / ".kuzushi/v3/campaigns").exists()
    assert not (evidence / "denied-fetch.jsonl").exists()
    for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
        assert not json.loads(path.read_text()).get("llmCalls"), path
    if stage == "restarted":
        ansi = next(evidence.glob("*-restarted-literal.ansi")).read_text()
        for sgr in re.findall(r"\x1b\[([\d;]*)m", ansi):
            assert not any(30 <= int(code) <= 38 or 40 <= int(code) <= 48
                           or 90 <= int(code) <= 107 for code in sgr.split(";") if code)
    save(evidence, stage, {"observations": 2, "humanDecisions": 0, "newProviderRequests": 0,
                         "targetSourceExecuted": False, "campaignsCreated": 0, "stateUnchanged": True})


if __name__ == "__main__":
    root, evidence, stage, home = sys.argv[1:]
    root, evidence, home = Path(root).resolve(), Path(evidence).resolve(), Path(home).resolve()
    if stage == "seed":
        seed(root, evidence, home)
    else:
        verify(root, evidence, stage)
