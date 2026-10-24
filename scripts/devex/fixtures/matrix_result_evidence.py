"""Owned same-title observations through a finite intercepted context experiment."""
import hashlib
import json
import shutil
import sys
from pathlib import Path

import context_matrix
from secret_settings import ledger

EXTRA = " literal 東京.rs"


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def seed(root, evidence, home):
    (root / EXTRA).write_text("// Owned literal source comments. Never compiled or executed.\n")
    context_matrix.seed(root, evidence, home)
    shutil.copyfile(Path(__file__).with_name("matrix_result_provider.mjs"), evidence / "provider.mjs")
    save(evidence, "source-files-before", {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ["main.rs", EXTRA]})


def verify(root, evidence, stage):
    context_matrix.verify(root, evidence, "finished" if stage == "exported" else stage)
    for name, digest in json.loads((evidence / "source-files-before.json").read_text()).items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
    if stage == "draft":
        return
    with ledger(root, evidence) as db:
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 15
        assert db.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 9
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 9
        assert db.execute("select count(*) from investigation_call_reservations where settled_at is null").fetchone()[0] == 0
    if stage == "recap":
        text = next(evidence.glob("*matrix-report.txt")).read_text()
        assert text.index("Shared allowance:") < text.index("baseline:")
        assert 'Location: "main.rs:1"' in text and 'Location: " literal 東京.rs:1"' in text
    if stage in ["exported", "restarted"]:
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        receipt = report["metadata"]["investigation"]
        assert receipt["kind"] == "context-matrix"
        assert receipt["observationCount"] == 15 and receipt["findingCount"] == 2
        assert len(report["findings"]) == 2 and receipt["reviewedCount"] == receipt["confirmedCount"] == 0
        assert {finding["location"]["file"] for finding in report["findings"]} == {"main.rs", EXTRA}
        for case, expected in zip(receipt["occurrence"]["cases"], [[3, 3], [2, 3], [1, 3]]):
            assert case["occurrence"]["completed"] == 3
            assert sorted(row["seen"] for row in case["occurrence"]["rows"]) == expected
        assert receipt["allowance"]["currentInvestigation"]["committedCalls"] == 9
        assert receipt["allowance"]["approval"]["limits"] == {"maxProviderCalls": 11, "protectedReviewCalls": 2}
    save(evidence, "evidence-" + stage, {"interceptedRequests": 9, "liveProviderRequests": 0, "targetSourceExecuted": False, "rawObservations": 15, "findingIdentities": 2, "caseRecurrence": [[3, 3], [2, 3], [1, 3]], "sourceUnchanged": True})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif sys.argv[3] == "hide-accounting":
        context_matrix.accounting_visibility(root, evidence, False)
    elif sys.argv[3] == "restore-accounting":
        context_matrix.accounting_visibility(root, evidence, True)
    else:
        verify(root, evidence, sys.argv[3])
