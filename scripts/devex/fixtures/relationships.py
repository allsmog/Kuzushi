"""Native Review metadata with one intercepted model request and no source execution."""
import hashlib
import csv
import json
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from rejected_context import execute


def seed(root, evidence, home):
    repo = Path(__file__).resolve().parents[3]
    (root / "hello.txt").write_text("Owned greeting data. Never executed.\n")
    credentials = home / ".kuzushi/relationship-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex": {"access": "offline-relationship-fixture", "expires": 99999999999999}}))
    credentials.chmod(0o600)
    shutil.copyfile(repo / "scripts/devex/fixtures/relationship_provider.mjs", evidence / "provider.mjs")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    bridge = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\nlanggraph_bridge_command = ' + json.dumps(bridge)
                     + '\n[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\nallow_env_token = false\n')
    for name in ["alpha", "beta"]:
        corpus = evidence / (name + ".jsonl")
        corpus.write_text(json.dumps({"file": "hello.txt", "line": 1, "title": "Labeled synthetic greeting observation " + name,
            "severity": "info", "class": name, "message": "Synthetic fixture; no security defect is claimed."}) + "\n")
        execute(root, home, evidence, "import-" + name, "workspace:import-findings", {"path": str(corpus), "tool": "owned-" + name})
    findings = execute(root, home, evidence, "before-findings", "findings:list", {})
    (evidence / "finding-data-shape.json").write_text(json.dumps(findings, indent=2))
    rows = findings["findings"]
    assert len(rows) == 2
    (evidence / "relationship-fingerprints.json").write_text(json.dumps([row["fingerprint"] for row in rows]))
    execute(root, home, evidence, "review-approval", "campaign:approve-allowance", {
        "investigationId": "relationship-review", "expectedRevision": 0, "model": "openai-codex:gpt-5.5",
        "maxProviderCalls": 4, "protectedReviewCalls": 2, "reason": "One intercepted duplicate proposal; no live provider request"})
    result = execute(root, home, evidence, "dedupe", "triage:dedupe", {"maxCandidates": 2, "maxGroups": 1, "maxEscalations": 0,
        "allowanceRef": {"schemaVersion": 1, "investigationId": "relationship-review", "revision": 1, "workId": "dedupe-review"}})
    assert result["relationshipsProposed"] == 1 and result["verdictsRecorded"] == 0 and result["linked"] == 0
    (evidence / "relationship-id.txt").write_text(result["relationshipIds"][0])
    (evidence / "source-before.json").write_text(json.dumps({"sourceSha256": hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest()}))
    ledger = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text("\n".join(json.dumps({"event": "phase_checkpoint_skipped", "phase": phase, "targetSnapshot": {"target": str(root), "dirty": False}, "recordedAtUnix": 1}) for phase in ["map", "scan"]) + "\n")
    (evidence / "accept-note.txt").write_text("Reviewed the two recorded observations.\nGrouping does not confirm a vulnerability.")
    (evidence / "remove-note.txt").write_text("Keep these observations separate after review.")
    verify(root, evidence, "proposed")


def verify(root, evidence, stage):
    expected = {"proposed": ("proposed", 1), "accepted": ("accepted", 2), "removed": ("removed", 3), "restarted": ("removed", 3)}[stage]
    identity = (evidence / "relationship-id.txt").read_text().strip()
    db_path = root / ".kuzushi/v3/index.sqlite3"
    for _ in range(30):
        with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True) as db:
            rows = db.execute("select payload_json from audit_events where subject='finding-relationship-v1' and json_extract(payload_json,'$.details.id')=? order by seq desc", [identity]).fetchall()
            record = json.loads(rows[0][0])["details"] if rows else {}
            if (record.get("state"), record.get("revision")) == expected: break
        time.sleep(0.1)
    assert (record["state"], record["revision"]) == expected
    with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True) as db:
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 2
        assert db.execute("select count(*) from finding_current").fetchone()[0] == 2
        assert db.execute("select count(*) from rekey_edges").fetchone()[0] == 0
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 0
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 1
        assert len(rows) == expected[1]
    assert len((evidence / "relationship-calls.jsonl").read_text().splitlines()) == 1
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest() == json.loads((evidence / "source-before.json").read_text())["sourceSha256"]
    if stage == "removed":
        verify_exports(root, evidence, expected)
    (evidence / (stage + "-relationship-check.json")).write_text(json.dumps({"state": expected[0], "revision": expected[1], "observations": 2,
        "identities": 2, "findingDecisions": 0, "rekeys": 0, "interceptedRequests": 1, "liveRequests": 0, "sourceExecuted": False}, indent=2) + "\n")


def verify_exports(root, evidence, expected):
    outputs = root / ".kuzushi/exports/relationships"
    outputs.mkdir(parents=True, exist_ok=True)
    for kind in ["json", "jsonl", "sarif", "markdown-bundle", "csv"]:
        path = outputs / ("bundle" if kind == "markdown-bundle" else "findings." + kind)
        execute(root, Path(os.environ["HOME"]), evidence, "export-" + kind, "workspace:export-findings", {"output": str(path), "format": kind})
        if kind == "csv":
            rows = list(csv.DictReader(path.open()))
            assert len(rows) == 2 and "relationships" not in rows[0]
            assert all("relationships" in row["format_omitted_fields"] for row in rows)
            continue
        document = json.loads((path / "manifest.json").read_text() if kind == "markdown-bundle" else path.read_text().splitlines()[0] if kind == "jsonl" else path.read_text())
        if kind == "jsonl":
            rows = [json.loads(line) for line in path.read_text().splitlines()[1:]]
        elif kind == "sarif":
            rows = [row for run in document["runs"] for row in run["results"]]
        else:
            rows = document["findings"]
        assert len(rows) == 2
        for row in rows:
            relation = row["properties"]["kuzushiRelationships"][0] if kind == "sarif" else row["relationships"][0]
            assert (relation["state"], relation["revision"]) == expected
            assert relation["from"]["runId"] and relation["to"]["runId"]
            verdict = row["properties"]["kuzushiReviewDecision"] if kind == "sarif" else row["reviewDecision"]
            assert verdict == "needs_review"
    assert len((evidence / "relationship-calls.jsonl").read_text().splitlines()) == 1
    (evidence / "export-check.json").write_text(json.dumps({"formats": 5, "state": expected[0], "revision": expected[1], "findingVerdicts": "needs_review", "extraProviderCalls": 0}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed": seed(root, evidence, Path(sys.argv[4]).resolve())
    else: verify(root, evidence, stage)
