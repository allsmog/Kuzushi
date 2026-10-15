"""Owned source capture and explicit review through real shared native dispatch."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from source_transition import seed, advance, command, LATER_SHA
from secret_settings import ledger, save
from catalog_dependencies import git, source_files


def captured(parent, evidence):
    root = parent / "repository"
    deadline = time.monotonic() + 20
    candidates = []
    while not candidates and time.monotonic() < deadline:
        for path in (root / ".kuzushi/v3/runs").glob("*/result.json"):
            result = json.loads(path.read_text())
            data = result.get("data", {})
            if data.get("sourceRef") and data.get("decisionId") is None:
                candidates.append((path, result))
        if not candidates:
            time.sleep(0.1)
    assert len(candidates) == 1, [str(path) for path, _ in candidates]
    path, result = candidates[0]
    data = result["data"]
    assert data["providerRequests"] == 0 and data["createsObservation"] is False
    assert data["reviewedSource"]["sourceGit"]["sha"] == LATER_SHA
    assert data["reviewedSource"]["sourceGit"]["dirty"] is True
    assert data["currentCheckoutApplicability"] == "not_assessed"
    save(evidence, "actual-tui-capture", {"resultPath": str(path), "data": data})


def decide(parent, evidence):
    root = parent / "repository"
    data = json.loads((evidence / "actual-tui-capture.json").read_text())["data"]
    finding = json.loads((root / ".kuzushi/v3/runs/revision-later/findings.json").read_text())[0]
    request = {"op": "decide", "finding": finding["fingerprint"], "sourceRef": data["sourceRef"],
               "verdict": "deferred", "reason": "Owned current dirty source explicitly reviewed; investigation is deferred"}
    note = root / "review-drift.txt"
    assert not note.exists()
    note.write_text("Owned inert source drift check.\n")
    env = dict(os.environ, HOME=str(evidence / "home"))
    failed = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root), "run",
                             "findings:review-source", "--input", "-"],
                            input=json.dumps(request), env=env, capture_output=True, text=True, timeout=60)
    (evidence / "stale-source.stdout.txt").write_text(failed.stdout)
    (evidence / "stale-source.stderr.txt").write_text(failed.stderr)
    assert failed.returncode != 0 and "Source content changed" in failed.stderr
    note.unlink()
    result = json.loads(command(root, evidence, "source-reviewed-decision", ["run", "findings:review-source",
                                "--run-id", "current-source-reviewed", "--input", "-"], request))
    assert result["data"]["reviewedSource"] == data["reviewedSource"]
    assert result["data"]["currentCheckoutApplicability"] == "matched_before_save"
    assert result["data"]["fixStatus"] == "not_assessed"
    save(evidence, "actual-source-decision", result["data"])
    exported = json.loads(command(root, evidence, "reviewed-export", ["findings", "--json"]))
    save(evidence, "reviewed-findings", exported)


def verify(parent, evidence):
    root = parent / "repository"
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
                  for name in ["finding_observations", "review_decisions", "investigation_call_reservations",
                               "investigation_work_attempts", "investigation_allowance_revisions"]}
        sources = [json.loads(row[0]) for row in db.execute("select json_extract(payload_json,'$.reviewedSource') "
                   "from finding_events where json_extract(payload_json,'$.reviewedSource') is not null")]
    assert list(counts.values()) == [4, 2, 0, 0, 0], counts
    expected = json.loads((evidence / "actual-source-decision.json").read_text())["reviewedSource"]
    assert sources == [expected]
    original = json.loads((evidence / "source-after.json").read_text())
    assert git(root, "rev-parse", "HEAD") == original["sha"] and source_files(root) == original["files"]
    save(evidence, "current-review-invariants", {"counts": counts, "reviewedSource": expected,
         "providerRequests": 0, "sourceExecuted": False, "newCommits": 0})


def exports(parent, evidence):
    root = parent / "repository"
    expected = json.loads((evidence / "actual-source-decision.json").read_text())["reviewedSource"]
    for kind in ["json", "jsonl", "sarif", "markdown-bundle"]:
        output = root / ".kuzushi/reports" / ("explicit-source-" + kind)
        command(root, evidence, "current-export-" + kind,
                ["run", "workspace:export-findings", "--input", "-"],
                {"format": kind, "output": str(output)})
        if kind == "json":
            actual = json.loads(output.read_text())["findings"][0]["reviewedSource"]
        elif kind == "jsonl":
            actual = json.loads(output.read_text().splitlines()[1])["reviewedSource"]
        elif kind == "sarif":
            record = json.loads(output.read_text())["runs"][0]["results"][0]["properties"]
            actual = record["kuzushiReviewedSource"]
            assert record["kuzushiCurrentCheckoutApplicability"] == "not_assessed"
        else:
            record = json.loads((output / "manifest.json").read_text())["findings"][0]
            actual = record["reviewedSource"]
            text = (output / record["path"]).read_text()
            assert "Explicitly reviewed source" in text and "does not recheck" in text
            assert expected["sourceGit"]["sha"] in text
        assert actual == expected, kind
    verify(parent, evidence)
    save(evidence, "current-source-exports", {"formats": ["json", "jsonl", "sarif", "markdown-bundle"],
         "reviewedSource": expected, "providerRequests": 0})


if __name__ == "__main__":
    parent, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    action = sys.argv[3]
    if action == "seed":
        seed(parent, evidence, Path(sys.argv[4]).resolve())
    elif action == "advance":
        advance(parent, evidence)
    elif action == "captured":
        captured(parent, evidence)
    elif action == "decide":
        decide(parent, evidence)
    elif action == "exports":
        exports(parent, evidence)
    else:
        verify(parent, evidence)
