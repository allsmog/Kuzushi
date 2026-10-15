"""Owned inert source-to-catalog recovery checks. No providers or source execution."""
import hashlib
import json
import re
import sys
import time
from pathlib import Path

from map_functionality import SOURCE, execute
from secret_settings import ledger


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seed(root, evidence, home):
    (root / "app.py").write_text(SOURCE)
    execute(root, evidence, home, "context", "context:build", {"enrichment": False})
    execute(root, evidence, home, "entry-points", "entry-points:extract", {})
    model = execute(root, evidence, home, "map", "threat-model:build", {
        "pipeline": "deterministic", "offline": True, "variantScan": False,
    }, "partial")
    assert model["document"]["dfd"]["nodes"] and model["document"]["dfd"]["flows"]
    assert (root / "app.py").read_text() == SOURCE
    verify_no_provider_work(root, evidence)


def verify_no_provider_work(root, evidence):
    with ledger(root, evidence) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts"]:
            if table in tables:
                assert connection.execute("select count(*) from " + table).fetchone()[0] == 0


def verify(root, evidence, state):
    source = root / "app.py"
    catalog_path = root / ".kuzushi/entry-points.json"
    initial = (evidence / "initial-catalog.sha256").read_text()
    assert digest(source) == (evidence / "drifted-source.sha256").read_text()
    if state == "stale":
        assert digest(catalog_path) == initial
        assert source.read_text().endswith("# Explicit source revision for catalog recovery.\n")
    else:
        catalog = json.loads(catalog_path.read_text())
        # Resolve the actual canonical context path recorded by the producer.
        context_result = json.loads((evidence / "context-result.json").read_text())
        context_path = Path(context_result["data"]["snapshotPath"])
        context_bytes = context_path.read_bytes()
        assert catalog["provenance"]["contextSnapshotSha256"] == "sha256:" + hashlib.sha256(context_bytes).hexdigest()
        routes = {row["route"]: row for row in catalog["entryPoints"] if row.get("route")}
        assert routes["/health"]["framework"] == "Flask"
        assert routes["/notes"]["framework"] == "FastAPI"
        if state == "rebuilt":
            assert digest(catalog_path) != initial
    verify_no_provider_work(root, evidence)
    (evidence / (state + "-check.json")).write_text(json.dumps({
        "catalogSha256": digest(catalog_path), "sourceSha256": digest(source),
        "priorCatalogPreserved": state == "stale", "providerCalls": 0,
        "sourceExecuted": False,
    }, indent=2) + "\n")


def await_rebuilt(root, evidence):
    deadline = time.monotonic() + 30
    while True:
        try:
            verify(root, evidence, "rebuilt")
            return
        except AssertionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def verify_tail(evidence):
    text = (evidence / "09-entries-tail-40x12.txt").read_text()
    match = re.search(r"rows (\d+)-(\d+)/(\d+)", text)
    assert match and match[2] == match[3], "narrow detail did not reach its final row"
    (evidence / "narrow-tail-check.json").write_text(json.dumps({
        "lastVisibleRow": int(match[2]), "totalRows": int(match[3]),
    }) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
        (evidence / "initial-catalog.sha256").write_text(digest(root / ".kuzushi/entry-points.json"))
    elif stage == "drift":
        path = root / "app.py"
        path.write_text(path.read_text() + "# Explicit source revision for catalog recovery.\n")
        (evidence / "drifted-source.sha256").write_text(digest(path))
    elif stage == "await-rebuilt":
        await_rebuilt(root, evidence)
    elif stage == "tail":
        verify_tail(evidence)
    else:
        verify(root, evidence, stage)
