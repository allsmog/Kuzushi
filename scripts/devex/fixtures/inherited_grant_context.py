"""Inherited grant history, refresh and damage recovery. No provider transport."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import allowance_inheritance
from secret_settings import ledger, save

RUN = "owned-inherited-context"


def run_file(root, name):
    return root / ".kuzushi/v3/runs" / RUN / name


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seed(root, evidence, home):
    allowance_inheritance.seed(root, evidence, home)
    retained = run_file(root, "inherited-allowance.json")
    value = json.loads(retained.read_text())
    assert value["schemaVersion"] == 1 and value["runId"] == RUN
    assert value["accountingRunId"] == "owned-parent-review" and value["work"] == "review"
    assert value["reference"]["revision"] == 1
    (evidence / "original-inherited-context.json").write_bytes(retained.read_bytes())
    save(evidence, "original-artifacts", {name: digest(run_file(root, name))
        for name in ["input.json", "result.json", "inherited-allowance.json"]})
    check(root, evidence, "initial")


def revise(root, evidence):
    fixture = Path(os.environ["KUZUSHI_NATIVE_BIN"]).with_name("allowance-inheritance-fixture")
    result = subprocess.run([str(fixture), str(root), "revise"], capture_output=True,
                            text=True, timeout=30)
    (evidence / "revision-stderr.txt").write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value == {"revision": 2, "committedCalls": 0, "liveProviderRequests": 0}
    save(evidence, "revision-proof", value)
    check(root, evidence, "revised")


def damage(root, evidence):
    run_file(root, "inherited-allowance.json").write_text("{}\n")
    check(root, evidence, "damaged", damaged=True)


def restore(root, evidence):
    run_file(root, "inherited-allowance.json").write_bytes(
        (evidence / "original-inherited-context.json").read_bytes())
    check(root, evidence, "restored")

def check_narrow(root, evidence):
    pages = sorted([*evidence.glob("*-inherited-40x12.txt"),
                    *evidence.glob("*-inherited-reading*-40x12.txt")])
    assert len(pages) == 10, [path.name for path in pages]
    body = " ".join(" ".join(path.read_text().splitlines()[2:7]) for path in pages)
    normalized = " ".join(body.split())
    for fact in ["Inherited Review grant: owned-inherited r1; 1 call total",
                 "Accounting run: owned-parent-review",
                 "Latest ledger at read: r2; 0/3 calls committed",
                 "not isolated child charges", "does not approve or start child work"]:
        assert fact in normalized, (fact, normalized)
    save(evidence, "narrow-grant-reading", {"capturedPages": len(pages),
        "originalGrantAndAccountingRunReadable": True, "latestLedgerReadable": True,
        "childUsageQualifierReadable": True, "liveProviderRequests": 0})
    check(root, evidence, "narrow")


def check(root, evidence, stage, damaged=False):
    original = json.loads((evidence / "original-artifacts.json").read_text())
    for name in ["input.json", "result.json"]:
        assert digest(run_file(root, name)) == original[name]
    assert (digest(run_file(root, "inherited-allowance.json")) != original["inherited-allowance.json"]) == damaged
    before = json.loads((evidence / "source-before.json").read_text())
    assert allowance_inheritance.source_hashes(root) == before
    with ledger(root, evidence) as db:
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 0
        approvals = [json.loads(row[0]) for row in db.execute(
            "select approval_json from investigation_allowance_revisions order by revision")]
    assert approvals[0]["limits"] == {"maxProviderCalls": 1, "protectedReviewCalls": 1}
    if stage != "initial":
        assert len(approvals) == 2 and approvals[1]["limits"] == {
            "maxProviderCalls": 3, "protectedReviewCalls": 1}
    assert not (root / ".kuzushi/v3/campaigns").exists()
    assert json.loads(run_file(root, "result.json").read_text())["status"] == "blocked"
    save(evidence, stage + "-grant-check", {"originalGrantRevision": 1,
        "latestGrantRevision": len(approvals), "committedCalls": 0,
        "protectedReviewRemaining": 1, "newJobs": 0, "liveProviderRequests": 0,
        "originalInputAndResultUnchanged": True, "sourceUnchanged": True,
        "retainedContextDamaged": damaged})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "revise":
        revise(root, evidence)
    elif stage == "damage":
        damage(root, evidence)
    elif stage == "restore":
        restore(root, evidence)
    elif stage == "narrow":
        check_narrow(root, evidence)
    else:
        check(root, evidence, stage)
