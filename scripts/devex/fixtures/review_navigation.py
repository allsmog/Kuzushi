"""Owned inert observations for keyboard ownership. No provider requests."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from map_functionality import execute


def source_hash(root):
    return hashlib.sha256((root / "navigation.txt").read_bytes()).hexdigest()


def seed(root, evidence, home):
    for name in ("app.py", "config.env"):
        (root / name).unlink(missing_ok=True)
    (root / "navigation.txt").write_text("Owned first observation\nOwned middle observation\nOwned last observation\n")
    rows = [dict(file="navigation.txt", line=index + 1, severity=severity,
                 title=f"Owned {name} observation", message="Labeled fixture; no defect claimed.",
                 **{"class": f"owned-{name}"})
            for index, (name, severity) in enumerate(zip(("first", "middle", "last"), ("high", "medium", "low")))]
    observations = evidence / "observations.jsonl"
    observations.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    execute(root, evidence, home, "import", "workspace:import-findings",
            {"path": str(observations), "tool": "owned-navigation"})
    execute(root, evidence, home, "context", "context:build", {"enrichment": False})
    (evidence / "source-before.sha256").write_text(source_hash(root))


def verify(root, evidence):
    assert source_hash(root) == (evidence / "source-before.sha256").read_text()
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 3
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 0
        if "investigation_call_reservations" in tables:
            assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 0
    (evidence / "navigation-check.json").write_text(json.dumps({"observations": 3,
        "decisions": 0, "providerRequests": 0, "sourceUnchanged": True,
        "sourceExecuted": False}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    evidence.mkdir(parents=True, exist_ok=True)
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence)
