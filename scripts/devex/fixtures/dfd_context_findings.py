"""Owned inert source and inactive context navigation. Zero provider calls."""
import hashlib
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

from context_comparison import run_tool
from context_diagram import document
from dfd_findings import file_path, report_rows, save


PATHS = ["src/a  b.tf", "src/scope#L7.tf", "src/`tag`.tf",
         "src/a b.tf", "src/scope.tf", "src/unrelated.tf"]


def facts(root):
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("pragma query_only=on")
        counts = {table: db.execute("select count(*) from " + table).fetchone()[0]
                  for table in ["finding_observations", "review_decisions"]}
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_work_attempts", "investigation_call_reservations"]:
            counts[table] = db.execute("select count(*) from " + table).fetchone()[0] if table in tables else 0
    counts["sources"] = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in PATHS}
    counts["context"] = hashlib.sha256((root / ".kuzushi/threat-models/manifest.json").read_bytes()).hexdigest()
    return counts


def prepare(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "src").mkdir(exist_ok=True)
    for name in PATHS:
        (root / name).write_text('cidr_blocks = ["0.0.0.0/0"]\n')
    native = os.environ["KUZUSHI_NATIVE_BIN"]
    run_tool(native, root, evidence, "owned-static-inspection", "iac-scan:scan", {})
    refs = {}
    for key, label, paths in [("selected", "Selected paths", PATHS[:3]), ("active", "Active unrelated", PATHS[-1:])]:
        graph = document(label)
        graph["attackSurface"]["entryPoints"] = [
            {"id": "EP-" + str(index), "name": "Owned configuration " + str(index),
             "path": path, "evidence": path + ":1", "line": 1,
             "targetElementIds": ["api", "request", "edge"]}
            for index, path in enumerate(paths, 1)]
        run_tool(native, root, evidence, "import-" + key, "threat-model:import",
                 {"document": graph, "label": label, "activate": True})
        refs[key] = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())["active"]
    save(evidence, "context-refs", refs)
    rows = report_rows(run_tool(native, root, evidence, "all-findings", "findings:list", {}))
    assert {file_path(row) for row in rows} == set(PATHS), rows
    expression = "files:" + json.dumps(PATHS[:3], separators=(",", ":"))
    selected = report_rows(run_tool(native, root, evidence, "exact-expression-query", "findings:list", {"filter": expression}))
    assert {file_path(row) for row in selected} == set(PATHS[:3]), selected
    (evidence / "exact-filter-command.txt").write_text("findings filter " + expression)
    before = facts(root)
    assert before["finding_observations"] == 6 and before["review_decisions"] == 0, before
    save(evidence, "before", before)
    save(evidence, "original-results", {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                                       for path in (root / ".kuzushi/v3/runs").glob("*/result.json")})


def verify(root, evidence, stage):
    before = json.loads((evidence / "before.json").read_text())
    assert facts(root) == before, "Navigation changed source, context, observations, decisions or budget work"
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json")), "Navigation created an investigation plan"
    originals = json.loads((evidence / "original-results.json").read_text())
    for name, digest in originals.items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
    readers = []
    for path in (root / ".kuzushi/v3/runs").glob("*/result.json"):
        if str(path.relative_to(root)) not in originals:
            run = json.loads(path.with_name("run.json").read_text())
            assert run["tool"] == "threat-model:read" and run["status"] == "completed", run
            readers.append(run["runId"])
    if stage == "restarted":
        ansi = next(evidence.glob("*-restarted-findings.ansi")).read_text()
        for sgr in re.findall(r"\x1b\[([\d;]*)m", ansi):
            assert not any(30 <= int(code) <= 38 or 40 <= int(code) <= 48 or 90 <= int(code) <= 107
                           for code in sgr.split(";") if code), "No-color restart emitted color"
    save(evidence, stage, {"observations": 6, "decisions": 0, "newProviderRequests": 0,
                          "investigationJobs": 0, "contextReadRuns": readers,
                          "activeContextUnchanged": True, "targetSourceExecuted": False})


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "prepare":
        prepare(root, evidence)
    else:
        verify(root, evidence, action)
