"""Verify accounting handoff after real offline generation and explicit Map acceptance."""
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
import generated_map


def seed(root, evidence):
    assert (root / ".git").is_dir(), "Use only the isolated harness repository"
    evidence.mkdir(parents=True, exist_ok=True)
    repo = Path(__file__).resolve().parents[3]
    # Reuse an existing local commit as test metadata. No commit is created.
    objects = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "--path-format=absolute", "--git-path", "objects"], text=True).strip()
    sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    info = root / ".git/objects/info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "alternates").write_text(objects + "\n")
    subprocess.run(["git", "-C", str(root), "update-ref", "refs/heads/fixture-baseline", sha], check=True)
    subprocess.run(["git", "-C", str(root), "symbolic-ref", "HEAD", "refs/heads/fixture-baseline"], check=True)
    (evidence / "git-baseline.json").write_text(json.dumps({
        "gitSha": sha, "baselineKind": "existing local commit reused as fixture Git metadata",
        "newCommitCreated": False, "fixtureWorktreeMatchesCommit": False,
    }, indent=2) + "\n")
    generated_map.seed(root, evidence)


def inspect(root, evidence, stage):
    state = root / ".kuzushi/v3"
    fixture = json.loads((state / "context-map-fixture.json").read_text())
    result = json.loads((state / "runs/context-result/result.json").read_text())
    reference = result["allowanceRef"]
    assert reference["investigationId"] == fixture["investigationId"]
    assert reference["revision"] == 1 and reference["schemaVersion"] == 1
    generated_map.verify(root, evidence, "accepted")
    plans = [json.loads(path.read_text()) for path in (state / "campaigns").glob("*/plan.json")]
    scans = [plan for plan in plans if plan.get("kind") == "scan-batch"]
    assert len(scans) == 1, "This journey approves exactly one new scan plan"
    scan = scans[0]
    assert scan["investigationId"] == fixture["investigationId"]
    assert scan["baseInput"]["threatModelRef"] == fixture["generated"]
    assert len(scan["jobs"]) == 3 and scan["workers"] == 1
    campaign = scan["campaignId"]
    (evidence / "scan-command.txt").write_text("campaign " + campaign)
    with sqlite3.connect((state / "index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        rows = connection.execute("select revision, approval_json from investigation_allowance_revisions where investigation_id=? order by revision", (fixture["investigationId"],)).fetchall()
        expected = 0 if stage == "missing" else 1 if stage == "draft" else 2
        assert len(rows) == expected, "No implicit or repeated allowance approval"
        if rows:
            approval = json.loads(rows[-1][1])
            assert approval["limits"] == {"maxProviderCalls": 5, "protectedReviewCalls": 2}
            if expected == 2:
                assert approval["workPlan"]["campaignId"] == campaign
                assert len(approval["workPlan"]["jobs"]) == 3
        assert connection.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 1
        assert connection.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 1
    assert not (state / "campaigns" / campaign / "queue.json").exists(), "Approval must not start jobs"
    (evidence / (stage + "-accounting.json")).write_text(json.dumps({
        "stage": stage, "investigationId": fixture["investigationId"], "campaignId": campaign,
        "approvedRevisions": expected, "committedCalls": 1, "totalCalls": 5,
        "protectedReviewCalls": 2, "discoveryJobsStarted": 0,
        "liveProviderCalls": 0, "fixtureKind": fixture["fixtureKind"],
    }, indent=2) + "\n")


def remove_approval(root, evidence):
    state = root / ".kuzushi/v3"
    fixture = json.loads((state / "context-map-fixture.json").read_text())
    with sqlite3.connect(state / "index.sqlite3") as connection:
        rows = connection.execute("select * from investigation_allowance_revisions").fetchall()
        (evidence / "removed-approval-rows.json").write_text(json.dumps(rows, indent=2) + "\n")
        connection.execute("delete from investigation_allowance_revisions where investigation_id=?", (fixture["investigationId"],))
    inspect(root, evidence, "missing")


def change_source(root, evidence):
    source = root / "main.rs"
    (evidence / "original-main.rs").write_bytes(source.read_bytes())
    head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    before = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"], text=True)
    source.write_text("fn changed() {}\n")
    assert subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip() == head
    after = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"], text=True)
    assert bool(before.strip()) == bool(after.strip()) is True
    (evidence / "same-sha-drift.json").write_text(json.dumps({
        "gitSha": head, "dirtyBefore": True, "dirtyAfter": True,
        "sourceContentChanged": True, "liveProviderCalls": 0,
    }, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "seed":
        seed(root, evidence)
    elif action == "remove-approval":
        remove_approval(root, evidence)
    elif action == "drift":
        change_source(root, evidence)
    elif action == "restore-source":
        (root / "main.rs").write_bytes((evidence / "original-main.rs").read_bytes())
        inspect(root, evidence, "restored-source")
    else:
        inspect(root, evidence, action)
