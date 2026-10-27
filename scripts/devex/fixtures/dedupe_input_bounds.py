"""Owned dedupe read limits with two intercepted requests and no source execution."""
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

from rejected_context import execute


def seed(root, evidence, home):
    repo = Path(__file__).resolve().parents[3]
    for name in ["main.rs", "app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    for name in ["hello.txt", " greeting.txt", "greeting.txt"]:
        (root / name).write_text("Owned inert greeting. Never executed.\n")
    configure_transport(repo, evidence, home)
    for name, source in [("alpha", "hello.txt"), ("beta", "hello.txt"),
        ("leading", " greeting.txt"), ("plain", "greeting.txt")]:
        path = evidence / (name + ".jsonl")
        path.write_text(json.dumps({"file": source, "line": 1, "severity": "info",
            "class": name, "title": "Labeled synthetic greeting " + name,
            "message": "Owned workflow fixture; no security defect is claimed."}) + "\n")
        execute(root, home, evidence, "import-" + name, "workspace:import-findings",
            {"path": str(path), "tool": "owned-" + name})
    data = execute(root, home, evidence, "findings-before", "findings:list", {})
    (evidence / "finding-data-shape.json").write_text(json.dumps(data, indent=2))
    path_of = lambda row: row.get("file_path", row.get("filePath", row.get("file")))
    assert len(data["findings"]) == 4
    assert {path_of(row) for row in data["findings"]} == {"hello.txt", " greeting.txt", "greeting.txt"}
    fingerprints = [row["fingerprint"] for row in data["findings"] if path_of(row) == "hello.txt"]
    excluded = [row["fingerprint"] for row in data["findings"] if path_of(row) != "hello.txt"]
    assert len(fingerprints) == len(excluded) == 2
    (evidence / "relationship-fingerprints.json").write_text(json.dumps(fingerprints))
    (evidence / "excluded-fingerprints.json").write_text(json.dumps(excluded))
    execute(root, home, evidence, "allowance", "campaign:approve-allowance", {
        "investigationId": "dedupe-input-review", "expectedRevision": 0,
        "model": "openai-codex:gpt-5.5", "maxProviderCalls": 4, "protectedReviewCalls": 2,
        "reason": "Two intercepted dedupe requests after an explicit read-limit correction"})
    value = {"maxCandidates": 2, "maxGroups": 1, "maxEscalations": 1,
        "allowanceRef": {"schemaVersion": 1, "investigationId": "dedupe-input-review",
            "revision": 1, "workId": "dedupe-read"}}
    (evidence / "run-command.txt").write_text("run triage:dedupe " + json.dumps(value))
    (evidence / "source-before.json").write_text(json.dumps({"sha256": source_hash(root)}))


def configure_transport(repo, evidence, home):
    provider = (repo / "scripts/devex/fixtures/relationship_provider.mjs").read_text()
    provider = provider.replace("appendFileSync, readFileSync", "appendFileSync, readFileSync, existsSync")
    marker = "globalThis.fetch = async (url, init) => {"
    guard = """
  const calls = join(directory, 'relationship-calls.jsonl');
  const callCount = existsSync(calls) ? readFileSync(calls, 'utf8').trim().split(String.fromCharCode(10)).length : 0;
  assert.ok(callCount < 2, 'At most two intercepted requests are permitted');
"""
    provider = provider.replace("confidence: 0.95", "confidence: 0.5")
    provider = provider.replace("const text = JSON.stringify({", "const text = JSON.stringify(callCount === 1 ? { same_root_cause: true, confidence: 0.95 } : {")
    body_marker = "  const body = JSON.parse(init.body);"
    assert provider.count(body_marker) == 1
    provider = provider.replace(body_marker, body_marker + "\n  assert.ok(!body.tools?.length, 'Metadata judgment must have no tools');\n  const excluded = JSON.parse(readFileSync(join(directory, 'excluded-fingerprints.json'), 'utf8'));\n  assert.ok(excluded.every(fp => !JSON.stringify(body.input).includes(fp)));")
    assert provider.count(marker) == 1
    (evidence / "provider.mjs").write_text(provider.replace(marker, marker + guard))
    credentials = home / ".kuzushi/offline-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex": {
        "access": "offline-relationship-fixture", "expires": 99999999999999}}))
    credentials.chmod(0o600)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    bridge = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n'
        + 'langgraph_bridge_command = ' + json.dumps(bridge)
        + '\n[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials))
        + '\nallow_env_token = false\n')


def source_hash(root):
    values = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ["hello.txt", " greeting.txt", "greeting.txt"]}
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def inspect(root, evidence, stage):
    records = []
    for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
        record = json.loads(path.read_text())
        if record.get("tool") == "triage:dedupe":
            result = json.loads((path.parent / "result.json").read_text())
            records.append((path.parent, record, result))
    failed = [row for row in records if row[1]["status"] == "failed"]
    completed = [row for row in records if row[1]["status"] == "completed"]
    assert len(failed) == 1
    assert "maxLedgerObservations" in failed[0][2]["output"]
    assert not failed[0][2].get("data", {}).get("relationshipsProposed")
    (evidence / "failed-replay.txt").write_text("replay " + failed[0][0].name)
    success = stage != "blocked"
    assert len(completed) == int(success)
    if success:
        data = completed[0][2]["data"]
        assert data["relationshipsProposed"] == 1 and data["verdictsRecorded"] == 0
        assert data["inputCoverage"]["observationsRead"] == 4
        assert data["inputCoverage"]["selectedCandidates"] == 2
        assert data["inputCoverage"]["omittedCandidates"] == 0
        assert data["escalated"] == 1 and not data["confirmationRefusals"]
        inputs = data["confirmationInputs"]
        assert inputs["basis"] == "current_workspace_files"
        assert len(inputs["files"]) == 1
        assert inputs["files"][0]["path"] == "hello.txt"
        assert inputs["files"][0]["readBytes"] == (root / "hello.txt").stat().st_size
        assert inputs["files"][0]["sha256"] == "sha256:" + hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest()

        (evidence / "completed-replay.txt").write_text("replay " + completed[0][0].name)
    calls = evidence / "relationship-calls.jsonl"
    assert (len(calls.read_text().splitlines()) if calls.exists() else 0) == 2 * int(success)
    db_path = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True) as db:
        for table, count in [("finding_observations", 4), ("rekey_edges", 0),
            ("review_decisions", 0), ("investigation_call_reservations", 2 * int(success))]:
            assert db.execute("select count(*) from " + table).fetchone()[0] == count
        proposals = db.execute("select count(*) from audit_events where subject='finding-relationship-v1'").fetchone()[0]
        assert proposals == int(success)
    assert source_hash(root) == json.loads((evidence / "source-before.json").read_text())["sha256"]
    (evidence / (stage + "-check.json")).write_text(json.dumps({
        "sourceUnchanged": True, "liveProviderRequests": 0, "targetSourceExecuted": False,
        "interceptedRequests": 2 * int(success), "findingObservations": 4,
        "humanDecisions": 0, "relationshipsProposed": int(success)}, indent=2) + "\n")


def wait(root, evidence, stage):
    deadline = time.monotonic() + 25
    while True:
        try:
            inspect(root, evidence, stage)
            return
        except (AssertionError, FileNotFoundError, json.JSONDecodeError, sqlite3.OperationalError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


if __name__ == "__main__":
    root, evidence, stage, *home = sys.argv[1:]
    root, evidence = Path(root).resolve(), Path(evidence).resolve()
    if stage == "seed":
        seed(root, evidence, Path(home[0]).resolve())
    else:
        wait(root, evidence, stage)
