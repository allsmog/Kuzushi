"""Inspect actual OAuth context receipts. No credentials, source execution or calls."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

CAMPAIGN = "live-luna-context-diagnostic"
RUN = CAMPAIGN + "-context-001-a1"


def evidence_state(root):
    state = root / ".kuzushi/v3"
    queue = json.loads((state / "campaigns" / CAMPAIGN / "queue.json").read_text())
    assert queue["jobs"]["context-001"]["state"] == "completed"
    result = json.loads((state / "runs" / RUN / "result.json").read_text())
    reference = result["data"]["modelRef"]
    assert result["status"] == "completed"
    with sqlite3.connect((state / "index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        calls = db.execute("select count(*),sum(review),sum(settled_at is null) from investigation_call_reservations").fetchone()
        attempts = db.execute("select count(*) from investigation_work_attempts").fetchone()[0]
        revision, approval = db.execute("select revision,approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()
    approval = json.loads(approval)
    assert calls == (7, 0, 0) and attempts == 5
    assert revision == 3 and approval["limits"] == {"maxProviderCalls": 10, "protectedReviewCalls": 2}
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest.get("active") is None
    sources = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ("app.py", "README.md")}
    return {"providerRequests": 7, "protectedReview": 2, "unresolvedRequests": 0,
            "workAttempts": 5, "allowanceRevision": 3, "sources": sources,
            "context": reference, "activeContext": manifest.get("active")}


def seed(root, evidence, home):
    before = evidence_state(root)
    (evidence / "live-context-before.json").write_text(json.dumps(before, indent=2) + "\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-6-luna"\n[runtime]\nthinking_level = "low"\n')
    (evidence / "context-command.txt").write_text("campaign " + CAMPAIGN)


def verify(root, evidence, stage):
    after = evidence_state(root)
    assert after == json.loads((evidence / "live-context-before.json").read_text())
    events = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    rows = [json.loads(line) for line in events.read_text().splitlines()]
    maps = [row for row in rows if row.get("event") == "phase_attempt_completed" and row.get("phase") == "map"]
    assert len(maps) == 1 and maps[0]["runRefs"] == [RUN]
    decisions = [row for row in rows if row.get("event") == "phase_attempt_disposition_recorded"
                 and row.get("attemptId") == maps[0]["attemptId"]]
    if stage == "pending":
        assert not decisions
    else:
        assert len(decisions) == 1 and decisions[0]["disposition"]["kind"] == "selected"
    after["mapAccepted"] = stage != "pending"
    (evidence / ("live-context-" + stage + ".json")).write_text(json.dumps(after, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, stage)
