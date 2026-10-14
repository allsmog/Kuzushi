"""Owned grouped-review records, one intercepted request, no source execution."""
import hashlib
import json
import os
import shutil
import sqlite3
import sys
from pathlib import Path
from rejected_context import execute


def seed(root, evidence, home):
    repo = Path(__file__).resolve().parents[3]
    (root / "hello.txt").write_text("Owned greeting observations. Never executed.\n")
    (root / "other.txt").write_text("Owned separate observation. Never executed.\n")
    credentials = home / ".kuzushi/group-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex": {"access": "offline-relationship-fixture", "expires": 99999999999999}}))
    credentials.chmod(0o600)
    provider = (repo / "scripts/devex/fixtures/relationship_provider.mjs").read_text()
    provider = provider.replace("duplicate_fingerprints: [fingerprints[1]]", "duplicate_fingerprints: fingerprints.slice(1)")
    (evidence / "provider.mjs").write_text(provider)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    bridge = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\nlanggraph_bridge_command = ' + json.dumps(bridge) + '\n[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\nallow_env_token = false\n')
    for batch in range(2):
        rows = [{"file": "hello.txt", "line": 1, "title": f"Labeled duplicate observation {index:02d}", "severity": "info", "class": f"greeting-{index:02d}", "message": "Labeled fixture. No security defect is claimed."} for index in range(batch * 32, (batch + 1) * 32)]
        path = evidence / f"batch-{batch}.jsonl"
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
        execute(root, home, evidence, f"import-{batch}", "workspace:import-findings", {"path": str(path), "tool": f"owned-{batch}"})
    rows = execute(root, home, evidence, "duplicates", "findings:list", {"limit": 100})["findings"]
    assert len(rows) == 64
    (evidence / "relationship-fingerprints.json").write_text(json.dumps([row["fingerprint"] for row in rows]))
    other = evidence / "other.jsonl"
    other.write_text(json.dumps({"file": "other.txt", "line": 1, "title": "Labeled separate observation", "severity": "info", "class": "separate", "message": "Labeled fixture. No security defect is claimed."}) + "\n")
    execute(root, home, evidence, "import-other", "workspace:import-findings", {"path": str(other), "tool": "owned-other"})
    execute(root, home, evidence, "approval", "campaign:approve-allowance", {"investigationId": "group-review", "expectedRevision": 0, "model": "openai-codex:gpt-5.5", "maxProviderCalls": 4, "protectedReviewCalls": 2, "reason": "One intercepted duplicate proposal on owned observations"})
    result = execute(root, home, evidence, "dedupe", "triage:dedupe", {"maxCandidates": 100, "maxGroups": 1, "maxEscalations": 0, "allowanceRef": {"schemaVersion": 1, "investigationId": "group-review", "revision": 1, "workId": "group-proposal"}})
    assert result["relationshipsProposed"] == 63
    for index, identity in enumerate(result["relationshipIds"]):
        execute(root, home, evidence, f"accept-{index}", "findings:relationship", {"id": identity, "state": "accepted", "note": "Reviewed labeled same-greeting observations; this is grouping only", "expectedRevision": 1})
    page = execute(root, home, evidence, "groups-before", "findings:groups", {})
    assert (page["totalFindings"], page["totalGroups"]) == (65, 2)
    group = next(row for row in page["groups"] if row["memberCount"] == 64)
    request = {"groupId": group["id"], "expectedRevision": page["revision"]}
    members = execute(root, home, evidence, "member-page-two", "findings:groups", {**request, "offset": 50})
    assert len(members["members"]) == 14
    selected = members["members"][0]
    links = execute(root, home, evidence, "selected-links", "findings:relationships", {"findingId": selected["findingId"]})["rows"]
    assert len(links) == 1
    (evidence / "selected-member.json").write_text(json.dumps(selected))
    (evidence / "group-before.json").write_text(json.dumps(page))
    (evidence / "source-before.json").write_text(json.dumps({name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ["hello.txt", "other.txt"]}))
    ledger = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text("\n".join(json.dumps({"event": "phase_checkpoint_skipped", "phase": phase, "targetSnapshot": {"target": str(root), "dirty": False}, "recordedAtUnix": 1}) for phase in ["map", "scan"]) + "\n")
    (evidence / "unlink-note.txt").write_text("Keep this labeled observation separate after review.")
    verify(root, evidence, "accepted")


def verify(root, evidence, stage):
    home = Path(os.environ["HOME"])
    page = execute(root, home, evidence, "verify-groups-" + stage, "findings:groups", {})
    expected = 3 if stage in ["removed", "restarted"] else 2
    assert (page["totalFindings"], page["totalGroups"]) == (65, expected)
    if expected == 3:
        assert sorted(row["memberCount"] for row in page["groups"]) == [1, 1, 63]
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 65
        assert db.execute("select count(*) from finding_current").fetchone()[0] == 65
        assert db.execute("select count(*) from rekey_edges").fetchone()[0] == 0
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 0
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 1
    assert len((evidence / "relationship-calls.jsonl").read_text().splitlines()) == 1
    before = json.load(open(evidence / "source-before.json"))
    assert all(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest for name, digest in before.items())
    (evidence / (stage + "-group-check.json")).write_text(json.dumps({"groups": expected, "observations": 65, "identities": 65, "findingDecisions": 0, "rekeys": 0, "interceptedRequests": 1, "liveRequests": 0, "sourceExecuted": False}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed": seed(root, evidence, Path(sys.argv[4]).resolve())
    else: verify(root, evidence, stage)
