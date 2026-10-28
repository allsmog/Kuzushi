"""Labeled inert file paths for diagram inspection. No model or source execution."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

from context_diagram import document

PATHS = [" a\nb ", "a b"]


def source_hashes(root):
    return {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in PATHS}


def seed(root, evidence):
    for path in PATHS:
        (root / path).write_text("Labeled inert source. Never executed.\n")
    value = document("Owned")
    value["attackSurface"]["entryPoints"] = [
        {"id": "literal-" + str(index), "name": "Owned source " + str(index),
         "description": "Labeled path evidence. No vulnerability claim.",
         "path": path, "evidence": path, "targetElementIds": ["api", "request", "edge"]}
        for index, path in enumerate(PATHS)]
    (root / "ctx.json").write_text(json.dumps(value))
    (evidence / "source-before.json").write_text(json.dumps(source_hashes(root)))


def verify(root, evidence):
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert len(manifest["models"]) == 1 and manifest["active"]
    index = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(index.as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_work_attempts", "investigation_call_reservations"]:
            if table in tables:
                assert connection.execute("select count(*) from " + table).fetchone()[0] == 0
    (evidence / "inspection-check.json").write_text(json.dumps({
        "paths": PATHS, "sourceUnchanged": True, "savedPlans": 0,
        "liveProviderRequests": 0, "sourceExecuted": False,
        "fixture": "labeled synthetic path evidence"}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        seed(root, evidence)
    else:
        verify(root, evidence)
