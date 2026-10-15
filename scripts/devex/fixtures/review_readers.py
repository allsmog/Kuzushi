"""Read-only Review controls over labeled policy observations, with no model work."""
import hashlib
import json
import sys
from pathlib import Path

from goal_review import seed as seed_goals
from investigation_brief import native, save
from secret_settings import ledger


def seed(root, evidence):
    seed_goals(root, evidence)
    (evidence / "reader-draft.txt").write_text("Unsent review draft\n東京 cursor evidence")
    save(evidence, "reader-baseline", facts(root, evidence))


def facts(root, evidence):
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
            for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]}
    return {"counts": counts, "sourceSha256": hashlib.sha256((root / "note.txt").read_bytes()).hexdigest()}


def verify(root, evidence):
    current = native(root, evidence, "reader-goals", "findings:goals", {})["data"]
    assert current["brief"]["reference"]["revision"] == 1 and current["total"] == 3
    assert all(row["assessment"] is None for row in current["rows"])
    snapshot = facts(root, evidence)
    assert snapshot == json.loads((evidence / "reader-baseline.json").read_text())
    assert snapshot["counts"]["finding_observations"] == 3
    assert all(value == 0 for key, value in snapshot["counts"].items() if key != "finding_observations")
    save(evidence, "readers-verified", {"facts": snapshot, "sourceExecuted": False,
        "providerRequests": 0, "findingDecisions": 0, "goalAssessments": 0, "syntheticObservations": True})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    {"seed": seed, "verify": verify}[sys.argv[3]](root, evidence)
