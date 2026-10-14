"""Labeled display-clock regression. Source, findings and SHAs use J98's fixture."""
import json
import sqlite3
import sys
from pathlib import Path
import review_source


def prepare(root, evidence):
    review_source.prepare(root, evidence)
    with sqlite3.connect(root / ".kuzushi/v3/index.sqlite3") as db:
        db.execute("update review_decisions set created_at = ? where id = 1", ("2099-01-01T00:00:00Z",))
        rows = db.execute("select id,decision_event_seq,decision_event_hash,decision_read_watermark from review_decisions order by id").fetchall()
    (evidence / "clock-provenance-before.json").write_text(json.dumps(rows, indent=2) + "\n")


def verify(root, evidence):
    review_source.verify(root, evidence)
    before = json.loads((evidence / "clock-provenance-before.json").read_text())
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        rows = db.execute("select id,decision_event_seq,decision_event_hash,decision_read_watermark from review_decisions order by id").fetchall()
        older = db.execute("select created_at from review_decisions where id = 1").fetchone()[0]
    assert [list(row) for row in rows[:2]] == before
    assert older == "2099-01-01T00:00:00Z" and rows[2][1] > rows[0][1]
    document = json.loads((root / ".kuzushi/reports/review-source.json").read_text())
    assert document["findings"][0]["reviewDecisionBasis"]["sourceApplicability"] == "latest_observation"
    (evidence / "clock-verification.json").write_text(json.dumps({"earlierEventProvenanceUnchanged": True,
        "displayClockIsSynthetic": True, "latestDecisionSource": "fixture-b", "sourceExecuted": False,
        "providerRequests": 0}, indent=2) + "\n")


if __name__ == "__main__":
    action, target, output = sys.argv[1:]
    {"prepare": prepare, "verify": verify}[action](Path(target).resolve(), Path(output).resolve())
