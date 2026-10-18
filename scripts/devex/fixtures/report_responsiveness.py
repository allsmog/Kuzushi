"""Hold real ledger contention and inspect exports without new investigation work."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from investigation_journey import calls, query_ledger, source_hashes


def snapshot(root):
    assert root.name == "fixture-target" and root.parent.name == "J121"
    before = json.loads((root.parent / "before.json").read_text())
    assert source_hashes(root) == before["sources"]
    with query_ledger(root) as db:
        counts = {table: db.execute("select count(*) from " + table).fetchone()[0]
                  for table in ["finding_observations", "review_decisions", "investigation_call_reservations"]}
    assert counts == {"finding_observations": 4, "review_decisions": 3, "investigation_call_reservations": 5}
    requests = calls(root.parent)
    assert len(requests) == 5 and all(row["liveProviderRequests"] == 0 for row in requests)
    campaigns = root / ".kuzushi/v3/campaigns"
    plans = {str(path.relative_to(campaigns)): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in campaigns.glob("*/*.json") if path.name in {"plan.json", "queue.json"}}
    return {"counts": counts, "source": before["sources"], "campaigns": plans, "interceptedRequests": 5}


def hold(root, evidence, label):
    with sqlite3.connect(root / ".kuzushi/v3/index.sqlite3", timeout=3) as db:
        mode = db.execute("pragma locking_mode=exclusive").fetchone()[0]
        assert mode == "exclusive"
        db.execute("begin immediate")
        (evidence / (label + "-held.json")).write_text(json.dumps({"pid": os.getpid(), "startedNs": time.monotonic_ns(), "lockingMode": mode}))
        time.sleep(4)
        db.rollback()
    (evidence / (label + "-released.json")).write_text(json.dumps({"pid": os.getpid(), "releasedNs": time.monotonic_ns()}))


def start(root, evidence, label):
    marker = evidence / (label + "-held.json")
    assert not marker.exists(), "Retain earlier contention attempts instead of overwriting them"
    with (evidence / (label + "-holder.log")).open("w") as output:
        process = subprocess.Popen([sys.executable, "-B", __file__, str(root), str(evidence), "hold", label],
                                   stdout=output, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 5
    while not marker.is_file() and time.monotonic() < deadline:
        assert process.poll() is None, "Owned lock holder stopped before acquisition"
        time.sleep(0.01)
    assert marker.is_file()
    assert process.poll() is None and json.loads(marker.read_text())["pid"] == process.pid


def verify(root, evidence):
    assert snapshot(root) == json.loads((evidence / "before-export.json").read_text())
    path = root / ".kuzushi/reports/responsive.sarif"
    report = json.loads(path.read_text())
    assert sum(len(run["results"]) for run in report["runs"]) == 2
    receipt = json.loads(path.with_name(path.name + ".investigation.json").read_text())
    assert receipt["observationCount"] == 4 and receipt["findingCount"] == 2
    assert receipt["allowance"]["currentInvestigation"]["committedCalls"] == 5
    held = list(evidence.glob("*-held.json"))
    assert len(held) == 6
    for marker in held:
        released = json.loads(marker.with_name(marker.name.replace("-held", "-released")).read_text())
        started = json.loads(marker.read_text())
        assert released["pid"] == started["pid"] and released["releasedNs"] > started["startedNs"]
    (evidence / "export-verification.json").write_text(json.dumps({"contentionWindows": 6,
        "sameFixedJobs": True, "sameObservationsAndDecisions": True, "sourceUnchanged": True,
        "newProviderRequests": 0, "sourceExecuted": False}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "before":
        (evidence / "before-export.json").write_text(json.dumps(snapshot(root), indent=2) + "\n")
    elif stage in {"hold", "start"}:
        (hold if stage == "hold" else start)(root, evidence, sys.argv[4])
    else:
        assert stage == "verify"
        verify(root, evidence)
