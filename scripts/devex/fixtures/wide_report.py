"""Read the actual completed wide study without rerunning discovery."""
import hashlib
import json
import sys
from pathlib import Path

from installed_scope_study import current_counts, save
from wide_semgrep import completed, hashes


def snapshot(root, evidence, decisions=9):
    plan = json.loads((root.parent / "wide-plan.json").read_text())
    campaign = root / ".kuzushi/v3/campaigns" / plan["campaignId"]
    counts = current_counts(root, evidence)
    assert counts["investigation_work_attempts"] == 24
    assert counts["finding_observations"] == 27 and counts["review_decisions"] == decisions
    assert counts["investigation_call_reservations"] == 0
    assert hashes(root) == json.loads((root.parent / "source-before.json").read_text())
    assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text()).get("active") is None
    return {"counts":counts, "planSha256":hashlib.sha256((campaign / "plan.json").read_bytes()).hexdigest(),
        "queueSha256":hashlib.sha256((campaign / "queue.json").read_bytes()).hexdigest(),
        "sourceFilesUnchanged":4105, "providerRequests":0, "sourceExecuted":False}


def seed(root, evidence, recovery=False):
    if recovery:
        for name in ["source-before.json", "wide-plan.json", "scanner-starts.jsonl"]:
            (evidence / name).write_bytes((root.parent / name).read_bytes())
        (evidence / "runtime-home.txt").write_text(str(root.parent / "home"))
        completed(root, evidence, "completed")
    plan = json.loads((root.parent / "wide-plan.json").read_text())
    (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    save(evidence, "reader-before", snapshot(root, evidence, 0 if recovery else 9))


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage in ["seed", "recover"]:
        seed(root, evidence, stage == "recover")
    else:
        state = snapshot(root, evidence)
        assert state == json.loads((evidence / "reader-before.json").read_text())
        save(evidence, stage + "-check", state)
