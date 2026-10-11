"""Report an archived owned matrix without rescanning or making model requests."""
import hashlib
import json
import shutil
import sqlite3
import sys
from pathlib import Path

BASE = Path("/tmp/kuzushi-context-matrix-20261007/tui/20261007-143450/J109")


def accounting(root):
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        calls = db.execute("select count(*),sum(settled_at is null),sum(review) from investigation_call_reservations").fetchone()
        attempts = db.execute("select count(*) from investigation_work_attempts").fetchone()[0]
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()[0])
    return {"calls": calls, "attempts": attempts, "limits": approval["limits"]}


def seed(root, evidence, home):
    assert (BASE / "manual-review.json").exists(), "J109 archived owned matrix is required"
    source = BASE / "fixture-target"
    assert "Owned greeting fixture, never executed" in (source / "main.rs").read_text()
    shutil.copytree(source, root, dirs_exist_ok=True)
    shutil.copytree(BASE / "home/.kuzushi", home / ".kuzushi", dirs_exist_ok=True)
    before = {"source": hashlib.sha256((root / "main.rs").read_bytes()).hexdigest(),
              "mirror": hashlib.sha256((root / ".kuzushi/threat-model.json").read_bytes()).hexdigest(),
              "accounting": accounting(root),
              "providerLog": hashlib.sha256((BASE / "matrix-calls.jsonl").read_bytes()).hexdigest()}
    (evidence / "before.json").write_text(json.dumps(before, indent=2) + "\n")
    plans = list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    matrix = next(json.loads(path.read_text()) for path in plans if json.loads(path.read_text()).get("kind") == "context-matrix")
    (evidence / "study-command.txt").write_text("campaign " + matrix["campaignId"])


def verify(root, evidence, stage):
    before = json.loads((evidence / "before.json").read_text())
    assert hashlib.sha256((root / "main.rs").read_bytes()).hexdigest() == before["source"]
    assert hashlib.sha256((root / ".kuzushi/threat-model.json").read_bytes()).hexdigest() == before["mirror"]
    assert json.loads(json.dumps(accounting(root))) == before["accounting"]
    assert hashlib.sha256((BASE / "matrix-calls.jsonl").read_bytes()).hexdigest() == before["providerLog"]
    if stage != "read":
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        receipt = report["metadata"]["investigation"]
        sidecar = json.loads((root / ".kuzushi/reports/findings.json.investigation.json").read_text())
        assert sidecar == receipt
        assert receipt["kind"] == "context-matrix" and "equivalence" not in receipt
        assert receipt["observationCount"] == 6 and receipt["findingCount"] == 1
        assert receipt["reviewedCount"] == 1 and receipt["confirmedCount"] == 0
        for index, seen in enumerate([3, 2, 1]):
            case = receipt["occurrence"]["cases"][index]["occurrence"]
            assert case["completed"] == 3 and case["rows"][0]["seen"] == seen
        assert len(report["findings"]) == 1
        assert "J110 labeled false positive" in json.dumps(report)
    (evidence / (stage + "-check.json")).write_text(json.dumps({"extraProviderRequests": 0,
        "sourceExecuted": False, "sourceAndContextUnchanged": True,
        "accountingUnchanged": True, "perCaseDenominators": [3, 3, 3]}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, stage)
