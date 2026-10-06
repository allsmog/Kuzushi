"""Read existing live validation receipts. Never copy credentials or launch work."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path


def evidence_state(root):
    campaign = root / ".kuzushi/v3/campaigns"
    context = json.loads((campaign / "live-luna-context-approved/queue.json").read_text())
    scans = json.loads((campaign / "live-luna-three-passes/queue.json").read_text())
    assert context["jobs"]["context-001"]["state"] == "failed"
    assert [job["state"] for job in scans["jobs"].values()] == ["completed", "failed", "failed"]
    database = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        calls = connection.execute("select count(*),sum(review),sum(settled_at is null) from investigation_call_reservations").fetchone()
        attempts = connection.execute("select count(*) from investigation_work_attempts").fetchone()[0]
    assert calls == (6, 0, 0) and attempts == 4
    sources = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ("app.py", "README.md")}
    return {"providerRequests": calls[0], "reviewRequests": calls[1], "unresolvedRequests": calls[2], "workAttempts": attempts, "sources": sources}


def seed(root, evidence, home):
    state = evidence_state(root)
    (evidence / "live-before.json").write_text(json.dumps(state, indent=2) + "\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-6-luna"\n[runtime]\nthinking_level = "low"\n')
    for name, campaign in [("context", "live-luna-context-approved"), ("scan", "live-luna-three-passes")]:
        (evidence / (name + "-command.txt")).write_text("campaign " + campaign)


def verify(root, evidence):
    state = evidence_state(root)
    assert state == json.loads((evidence / "live-before.json").read_text())
    (evidence / "live-after.json").write_text(json.dumps(state, indent=2) + "\n")


if __name__ == "__main__":
    target, artifacts, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(target, artifacts, Path(sys.argv[4]).resolve())
    else:
        verify(target, artifacts)
