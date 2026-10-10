"""Decision-source UX fixture. Findings and commit metadata are synthetic."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def prepare(root, evidence):
    executable = Path(os.environ["KUZUSHI_REVIEW_SOURCE_TEST_BIN"])
    env = dict(os.environ, KUZUSHI_REVIEW_SOURCE_FIXTURE_OUT=str(root))
    result = subprocess.run([str(executable), "--exact", "app::view_hydration::reader::review_source::tests::prepare_native_review_source_fixture", "--nocapture"],
                            env=env, text=True, capture_output=True, timeout=30, check=True)
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "fixture-preparation.log").write_text(result.stdout + result.stderr)
    receipt = json.loads((root / "fixture-receipt.json").read_text())
    assert receipt["findingsAreSynthetic"] and receipt["commitMetadataIsSynthetic"]
    assert receipt["providerRequests"] == 0 and receipt["sourceExecuted"] is False
    (evidence / "open.txt").write_text("open " + receipt["findingFingerprint"])
    (evidence / "source-before.json").write_text(json.dumps(source_state(root), indent=2) + "\n")


def source_state(root):
    files = ["src/lib.rs", "README.md", ".kuzushi/v3/runs/fixture-a/run.json", ".kuzushi/v3/runs/fixture-b/run.json"]
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in files}


def verify(root, evidence):
    assert source_state(root) == json.loads((evidence / "source-before.json").read_text())
    output = root / ".kuzushi/reports/review-source.json"
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root), "export", "--format", "json", "--out", str(output), "--allow-empty"],
                            text=True, capture_output=True, timeout=30, check=True)
    (evidence / "export.log").write_text(result.stdout + result.stderr)
    document = json.loads(output.read_text())
    assert document["count"] == 1
    finding = document["findings"][0]
    assert finding["reviewDecision"] == "deferred" and finding["reviewDecisionAuthor"] == "human"
    assert finding["reviewDecisionBasis"]["runId"] == "fixture-b"
    assert finding["reviewDecisionBasis"]["sourceComparison"] == "not_reobserved"
    db_path = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True) as db:
        count = db.execute("select count(*) from review_decisions").fetchone()[0]
    assert count == 3, count
    (evidence / "verification.json").write_text(json.dumps({"decisionsRetained": 3, "newDecisionSource": "fixture-b", "sourceUnchanged": True,
        "providerRequests": 0, "sourceExecuted": False, "findingsAreSynthetic": True, "commitMetadataIsSynthetic": True}, indent=2) + "\n")


if __name__ == "__main__":
    action, target, output = sys.argv[1:]
    {"prepare": prepare, "verify": verify}[action](Path(target).resolve(), Path(output).resolve())
