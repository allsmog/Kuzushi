"""Read the retained real scope refinement without accepting or extending it."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CONTROL = REPO / "scripts/devex/artifacts/scope-balanced-refinement-current-20261026/control"


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def immutable_files(root, prepared, live):
    state = root / ".kuzushi/v3"
    paths = list((state / "scan-scopes").rglob("*.json"))
    paths += list((root / ".kuzushi/threat-models").rglob("*.json"))
    paths += list((state / "campaigns").glob("*/plan.json"))
    paths += list((state / "campaigns").glob("*/queue.json"))
    paths += list((state / "runs" / live["runId"]).glob("*.json"))
    source = REPO / "scripts/devex/artifacts/retained-scope-investigation-current-20261027/control/original-before.json"
    recorded = read(source)
    source_paths = [name for name in recorded if not name.startswith((".kuzushi/", ".git/"))]
    assert len(source_paths) == 602
    for name in source_paths:
        path = root / name
        assert digest(path) == recorded[name], name
        paths.append(path)
    paths.append(Path(prepared["operatorHome"]) / ".kuzushi/v3/config.toml")
    return {str(path): digest(path) for path in paths}


def verify(evidence, stage, home=None):
    prepared, live = read(CONTROL / "prepared.json"), read(CONTROL / "live-result.json")
    root = Path(prepared["target"])
    state = root / ".kuzushi/v3"
    reference = live["scopeReference"]
    record = read(state / "scan-scopes/revisions" / (reference["recordHash"] + ".json"))
    assert record["revision"] == 3 and record["acceptance"] is None
    assert len(record["draft"]["scopes"]) == 7
    assert record["draft"]["sharedScope"]["id"] == "shared-contracts"
    assert not record["draft"]["sharedDiscovery"]
    revisions = list((state / "scan-scopes/revisions").glob("*.json"))
    assert len(revisions) == 3 and all(read(path)["acceptance"] is None for path in revisions)
    assert read(root / ".kuzushi/threat-models/manifest.json").get("active") is None
    with sqlite3.connect((state / "index.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0]
                  for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts", "investigation_allowance_revisions"]}
        assert counts == {"finding_observations": 0, "review_decisions": 0,
                          "investigation_call_reservations": 3, "investigation_work_attempts": 3,
                          "investigation_allowance_revisions": 3}, counts
        limits = [json.loads(row[0])["limits"]["maxProviderCalls"]
                  for row in db.execute("select approval_json from investigation_allowance_revisions")]
        assert sorted(limits) == [1, 2, 3]
        assert db.execute("select count(*) from investigation_call_reservations where settled_at is null").fetchone()[0] == 0
    if stage == "compact":
        frames = "\n".join(path.read_text() for path in evidence.glob("*-40x12*.txt"))
        assert "504/602" in frames and "filenames" in frames
        assert "504/602 files." not in frames
    hashes = immutable_files(root, prepared, live)
    baseline = evidence / "immutable-before.json"
    if stage == "seed":
        assert home is not None and not baseline.exists()
        baseline.write_text(json.dumps(hashes, indent=2) + "\n")
        config = home / ".kuzushi/v3/config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text('model = "openai-codex:gpt-6-luna"\n[runtime]\nthinking_level = "low"\n')
        request = {"investigationId": prepared["investigation"], "runId": live["runId"]}
        (evidence / "read-allowance.txt").write_text("run campaign:allowance " + json.dumps(request))
    else:
        assert hashes == read(baseline)
    assert not (evidence / "denied-fetch.jsonl").exists()
    result = {"sourceFilesUnchanged": 602, "recordedScopeRevision": 3, "primaryScopes": 7,
              "sharedContextMembers": 8, "scopeAccepted": False, "contextActive": False,
              "oldCommittedCalls": 3, "newProviderRequests": 0, "remainingAllowance": 0,
              "dollarCost": "unknown", "ledgerCounts": counts, "immutableObjectsUnchanged": True,
              "targetSourceExecuted": False, "credentialsCopied": False}
    (evidence / (stage + "-check.json")).write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).resolve() if len(sys.argv) == 4 else None)
