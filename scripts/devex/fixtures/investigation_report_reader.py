"""Read the completed owned investigation without new jobs or provider requests."""
import json
import sqlite3
import sys
from pathlib import Path
from investigation_journey import source_hashes, calls


def state(root):
    assert root.name == "fixture-target" and root.parent.name == "J121"
    before = json.loads((root.parent / "before.json").read_text())
    assert source_hashes(root) == before["sources"]
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        counts = {table: db.execute("select count(*) from " + table).fetchone()[0]
            for table in ["finding_observations", "review_decisions", "investigation_call_reservations"]}
    assert counts == {"finding_observations": 4, "review_decisions": 3, "investigation_call_reservations": 4}
    assert len(calls(root.parent)) == 4
    return {"counts": counts, "sources": before["sources"], "providerRequests": 4}


def verify_pages(evidence):
    paths = sorted(evidence.glob("*-reader-page-*.txt"))
    assert len(paths) == 30
    text = " ".join(" ".join(path.read_text().split()) for path in paths)
    for phrase in ["2 reviewed", "4 producer observations", "3 completed", "0 pending",
            "Source:", "dirty", "Context: frozen", "Model: openai-codex:gpt-5.5",
            "4 committed", "6 calls", "protected review", "cost not recorded",
            "no complete coverage claim", "study/history", "provenance", "export"]:
        assert phrase in text, "Required report content never reached the narrow viewport: " + phrase
    assert len({path.read_text() for path in paths}) > 8


def main():
    root, evidence = [Path(value) for value in sys.argv[1:3]]
    stage = sys.argv[3]
    current = state(root)
    if stage == "before":
        (evidence / "reader-before.json").write_text(json.dumps(current, indent=2) + "\n")
    else:
        assert current == json.loads((evidence / "reader-before.json").read_text())
        verify_pages(evidence)
        (evidence / "reader-after.json").write_text(json.dumps({**current, "newRequests": 0, "newDecisions": 0, "sourceExecuted": False}, indent=2) + "\n")


if __name__ == "__main__":
    main()
