"""Owned decision receipts name observed source, independently of dirty checkout."""
import json
import sys
from pathlib import Path

from source_transition import seed, advance, command, LATER, LATER_SHA
from secret_settings import ledger, save


def cli_decisions(parent, evidence):
    root = parent / "repository"
    observations = json.loads((root / ".kuzushi/v3/runs" / LATER / "findings.json").read_text())
    finding = observations[0]
    reference = finding.get("identity_id") or finding["fingerprint"]
    args = ["decision", reference, "--verdict", "deferred", "--reason",
            "Owned receipt keeps observed source; current checkout is unassessed"]
    result = json.loads(command(root,evidence,"cli-json-decision",args + ["--json"]))
    receipt = result["sourceReceipt"]
    assert receipt["schemaVersion"] == 1 and receipt["decisionId"] == result["decisionId"]
    assert receipt["sourceReadError"] is None
    basis = receipt["sourceBasis"]
    assert basis["runId"] == LATER and basis["sourceGit"]["sha"] == LATER_SHA
    assert basis["sourceGit"]["dirty"] is False
    assert result["currentCheckoutApplicability"] == "not_assessed"
    plain = command(root,evidence,"cli-plain-decision",["decision",reference,
        "--verdict","needs_review","--reason","Owned receipt needs current-source review"])
    assert "Decision evidence: recorded observation revision-later" in plain
    assert LATER_SHA in plain and "Saving a decision does not assess the current checkout" in plain
    assert "carry forward" not in plain
    save(evidence,"cli-source-receipt",result)


def verify(parent, evidence):
    root = parent / "repository"
    with ledger(root,evidence) as db:
        tables={row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts={name:db.execute("select count(*) from "+name).fetchone()[0] if name in tables else 0 for name in
            ["finding_observations","review_decisions","investigation_call_reservations","investigation_work_attempts","investigation_allowance_revisions"]}
    assert list(counts.values()) == [4,3,0,0,0], counts
    original=json.loads((evidence/'source-after.json').read_text())
    from catalog_dependencies import git, source_files
    assert git(root,'rev-parse','HEAD') == original['sha']
    assert source_files(root) == original['files']
    save(evidence,"receipt-invariants",{"counts":counts,"providerRequests":0,"sourceExecuted":False,"newCommits":0})


if __name__ == '__main__':
    parent,evidence=[Path(value).resolve() for value in sys.argv[1:3]]
    action=sys.argv[3]
    if action=='seed': seed(parent,evidence,Path(sys.argv[4]).resolve())
    elif action=='advance': advance(parent,evidence)
    elif action=='cli': cli_decisions(parent,evidence)
    else: verify(parent,evidence)
