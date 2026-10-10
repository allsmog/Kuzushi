"""Observe native readiness reading without manufacturing a result."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
assert sys.argv[3] == "unstarted"
before = json.loads((evidence / "source-before.json").read_text())
source = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in before}
assert source == before
state = root / ".kuzushi"
assert not list((state / "v3/runs").glob("*/run.json"))
assert not list((state / "v3/campaigns").glob("*/plan.json"))
assert not (state / "threat-models/manifest.json").exists()
names = ["finding_observations", "investigation_call_reservations", "investigation_work_attempts", "review_decisions"]
counts = {name: 0 for name in names}
database = state / "v3/index.sqlite3"
if database.exists():
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        counts = {name: connection.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0 for name in names}
assert all(value == 0 for value in counts.values()), counts
(evidence / "readiness-unstarted.json").write_text(json.dumps({"source": source, "counts": counts, "runCount": 0, "planCount": 0}, indent=2) + "\n")
