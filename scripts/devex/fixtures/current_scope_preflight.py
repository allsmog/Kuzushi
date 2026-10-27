"""Read one owned unapproved scope plan with model transport blocked."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CONTROL = REPO / "scripts/devex/artifacts/scope-proposal-current-20261026/control"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(evidence, stage):
    prepared = json.loads((CONTROL / "prepared.json").read_text())
    root = Path(prepared["target"])
    source = json.loads((CONTROL / "source-hashes.json").read_text())
    assert len(source) == 602
    assert all(digest(root / name) == sha for name, sha in source.items())
    state = root / ".kuzushi/v3"
    plan = state / "campaigns" / prepared["campaign"] / "plan.json"
    assert digest(plan) == prepared["planFileSha256"]
    document = json.loads(plan.read_text())
    assert len(document["jobs"]) == document["workers"] == 1
    assert document["jobs"][0]["tool"] == "pack:suggest-scopes"
    assert document["jobs"][0]["input"]["threatModelRef"] == prepared["contextRef"]
    assert document["jobs"][0]["input"]["thinkingLevel"] == "low"
    assert not list((state / "campaigns").glob("*/queue.json"))
    manifest = root / ".kuzushi/threat-models/manifest.json"
    assert digest(manifest) == prepared["contextManifestSha256"]
    assert json.loads(manifest.read_text()).get("active") is None
    config = Path(prepared["operatorHome"]) / ".kuzushi/v3/config.toml"
    assert digest(config) == prepared["operatorConfigFileSha256"]
    assert not (evidence / "denied-fetch.jsonl").exists()
    with sqlite3.connect((state / "index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute('select count(*) from "' + name + '"').fetchone()[0]
            for name in tables if name.startswith("investigation_")}
        assert all(value == 0 for value in counts.values()), counts
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 0
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 0
    for path in (state / "runs").glob("*/run.json"):
        record = json.loads(path.read_text())
        assert not record.get("llm_calls") and not record.get("llmCalls"), path
    value = {"sourceFilesUnchanged": 602, "planUnchanged": True,
        "scopeAccepted": False, "contextActive": False, "jobsStarted": 0,
        "modelRequests": 0, "targetSourceExecuted": False,
        "networkFetchAttempts": 0, "investigationTableCounts": counts}
    (evidence / (stage + "-check.json")).write_text(json.dumps(value, indent=2) + "\n")


if __name__ == "__main__":
    evidence, stage = sys.argv[1:]
    verify(Path(evidence).resolve(), stage)
