"""Authenticate preparation artifacts and unchanged primary Map history."""
import hashlib
import json
import sys
from pathlib import Path

from secret_settings import ledger


def phase_history(root):
    directory = root / ".kuzushi/v3/workflow"
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in directory.glob("phase-attempts*.jsonl") if path.read_bytes().strip()}


def verify(root, evidence, stage):
    source = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
              for name in ["package.json", "main.rs"]}
    assert source == json.loads((evidence / "source-before.json").read_text())
    with ledger(root, evidence) as db:
        present = db.execute("select 1 from sqlite_master where type='table' and name='investigation_call_reservations'").fetchone() is not None
        reservations = db.execute("select count(*) from investigation_call_reservations").fetchone()[0] if present else None
        assert reservations in [None, 0]
    history = phase_history(root)
    if stage == "before-map":
        assert not history, "preparation created a phase attempt"
    elif stage == "accepted":
        assert history, "primary Map history is absent"
        (evidence / "accepted-map-history.json").write_text(json.dumps(history) + "\n")
    else:
        assert history == json.loads((evidence / "accepted-map-history.json").read_text())
    catalog = root / ".kuzushi/entry-points.json"
    assert catalog.is_file()
    document = json.loads(catalog.read_text())
    snapshot = (root / ".kuzushi/context-snapshot.json").read_bytes()
    assert document["provenance"]["contextSnapshotSha256"] == "sha256:" + hashlib.sha256(snapshot).hexdigest()
    (evidence / (stage + "-preparation-check.json")).write_text(json.dumps({
        "sourceUnchanged": True, "providerReservations": reservations, "accountingTablePresent": present, "phaseHistory": history,
        "catalogSha256": hashlib.sha256(catalog.read_bytes()).hexdigest(),
        "sourceExecuted": False,
    }, indent=2) + "\n")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3])
