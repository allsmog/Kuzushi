"""Owned static configuration and diagram links. No provider or source execution."""
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path

from context_comparison import run_tool
from context_diagram import document


PATHS = ["src/a b.tf", "src/a,b.tf", "src/a b.tf.extra.tf", "src/unrelated.tf"]


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def report_rows(output):
    return output["data"]["findings"]


def file_path(row):
    return row.get("filePath", row.get("file_path"))


def facts(root):
    database = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(database.as_uri() + "?mode=rw", uri=True) as db:
        db.execute("pragma query_only=on")
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0]
                  for name in ["finding_observations", "review_decisions"]}
    counts["sources"] = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in PATHS}
    counts["context"] = hashlib.sha256((root / ".kuzushi/threat-models/manifest.json").read_bytes()).hexdigest()
    counts["results"] = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in (root / ".kuzushi/v3/runs").glob("*/result.json")}
    return counts


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "src").mkdir(exist_ok=True)
    for name in PATHS:
        (root / name).write_text('cidr_blocks = ["0.0.0.0/0"]\n')
    native = os.environ["KUZUSHI_NATIVE_BIN"]
    run_tool(native, root, evidence, "owned-static-inspection", "iac-scan:scan", {})
    graph = document("Owned source")
    graph["attackSurface"]["entryPoints"] = [
        {"id": "EP-" + str(index), "name": "Owned configuration " + str(index),
         "path": path, "evidence": path + ":1", "line": 1,
         "targetElementIds": ["api", "request", "edge"]}
        for index, path in enumerate(PATHS[:2], 1)]
    run_tool(native, root, evidence, "owned-diagram", "threat-model:import",
             {"document": graph, "label": "Owned evidence paths", "activate": True})
    rows = report_rows(run_tool(native, root, evidence, "all-findings", "findings:list", {}))
    assert {file_path(row) for row in rows} == set(PATHS), rows
    selected = report_rows(run_tool(native, root, evidence, "exact-file-query", "findings:list",
                                   {"filePaths": PATHS[:2]}))
    assert {file_path(row) for row in selected} == set(PATHS[:2]), selected
    before = facts(root)
    assert before["finding_observations"] == 4 and before["review_decisions"] == 0, before
    save(evidence, "before", before)


def verify(root, evidence, stage):
    before = json.loads((evidence / "before.json").read_text())
    assert facts(root) == before, "Navigation changed observations, decisions, context, source or tool results"
    assert not (root / ".kuzushi/v3/campaigns").exists()
    save(evidence, stage, {"observations": 4, "decisions": 0, "newProviderRequests": 0,
                          "navigationJobs": 0, "targetSourceExecuted": False, "stateUnchanged": True})


if __name__ == "__main__":
    root, evidence = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    if sys.argv[3] == "prepare":
        prepare(root, evidence)
    else:
        verify(root, evidence, sys.argv[3])
