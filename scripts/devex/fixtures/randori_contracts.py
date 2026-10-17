"""Owned draft artifacts and intercepted synthesis. No source execution or live inference."""
import hashlib
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path

from secret_settings import ledger, save

MODEL = "openai-codex:gpt-5.5"
INVESTIGATION = "owned-randori"
DRAFT = ".kuzushi/draft "


def command(evidence, name, tool, value):
    (evidence / (name + "-command.txt")).write_text("run " + tool + " " + json.dumps(value))


def document():
    return {"version": "2.0", "methodology": "pasta", "title": "Owned note catalog",
        "systemContext": "Labeled protocol fixture for artifact consumption. No model accuracy or vulnerability claim.",
        "dfd": {"nodes": [
            {"id": "operator", "type": "external-entity", "name": "Operator", "description": "Supplies note text", "trustZone": "external"},
            {"id": "catalog", "type": "process", "name": "Note catalog", "description": "Labels owned note text", "trustZone": "repository"}],
            "flows": [{"id": "notes", "sourceId": "operator", "targetId": "catalog", "description": "Owned note text", "trustBoundaryIds": []}],
            "trustBoundaries": []}, "threats": [], "summary": {"total": 0, "bySeverity": {}, "byCategory": {}}}


def hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ["package.json", "note.ts"]}


def prepare(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "package.json").write_text('{"name":"owned-note-catalog","private":true}\n')
    (root / "note.ts").write_text('export const label = "Owned note catalog"; // Never executed.\n')
    save(evidence, "protocol-document", document())
    repo = Path(__file__).resolve().parents[3]
    provider = evidence / "provider.mjs"
    shutil.copyfile(Path(__file__).with_name("randori_provider.mjs"), provider)
    credentials = home / ".kuzushi/randori-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex": {"access": "offline-randori-fixture", "expires": 99999999999999}}))
    credentials.chmod(0o600)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    bridge = ["node", "--import", str(provider), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model="' + MODEL + '"\n[runtime]\nthinking_level="medium"\nlanggraph_bridge_command=' + json.dumps(bridge)
        + '\n[runtime.anthropic_oauth]\ncredentials_path=' + json.dumps(str(credentials)) + '\nallow_env_token=false\n')
    approval = {"investigationId": INVESTIGATION, "expectedRevision": 0, "model": MODEL,
        "maxProviderCalls": 4, "protectedReviewCalls": 2, "reason": "Two explicit intercepted drafts; no live inference or follow-up jobs"}
    command(evidence, "approve", "campaign:approve-allowance", approval)
    for name, bound, replace in [("unbound", False, False), ("draft", True, False), ("preserve", True, False), ("replace", True, True)]:
        value = {"outputDir": DRAFT}
        if bound:
            value["allowanceRef"] = {"schemaVersion": 1, "investigationId": INVESTIGATION, "revision": 1, "workId": name}
        if replace:
            value["preserveUserEdits"] = False
        command(evidence, name, "randori:pasta", value)
    for folder, body in [("malformed-stage", document()), ("bad-primary", "not JSON")]:
        path = root / ".kuzushi" / folder
        path.mkdir(parents=True)
        (path / "normalized-threat-model.json").write_text(json.dumps(body) if isinstance(body, dict) else body)
        (path / "pasta-s2.json").write_text("not JSON" if folder == "malformed-stage" else "{}")
    empty = root / ".kuzushi/empty-stage"
    empty.mkdir(parents=True)
    (empty / "pasta-s2.json").write_text("{}")
    for name, folder, tool in [("read", DRAFT, "randori:threat-model"), ("canonical", DRAFT, "threat-model:read"),
        ("partial", ".kuzushi/malformed-stage", "randori:threat-model"), ("bad", ".kuzushi/bad-primary", "randori:threat-model"),
        ("empty", ".kuzushi/empty-stage", "randori:threat-model")]:
        command(evidence, name, tool, {"outputDir": folder, "methodology": "pasta"})
    command(evidence, "import", "threat-model:import", {"path": str(root / DRAFT / "normalized-threat-model.json"), "methodology": "pasta", "activate": False})
    command(evidence, "status", "campaign:allowance", {"investigationId": INVESTIGATION})
    save(evidence, "source-before", hashes(root))


def results(root):
    rows = []
    for path in sorted((root / ".kuzushi/v3/runs").glob("*/result.json")):
        value = json.loads(path.read_text())
        if isinstance(value.get("data"), dict):
            rows.append((path.parent.name, value))
    return rows


def same_directory(root, actual, expected):
    if not isinstance(actual, str):
        return False
    path = Path(actual)
    return (path if path.is_absolute() else root / path).resolve() == (root / expected).resolve()


def inspect(root, evidence, stage):
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    calls = evidence / "randori-calls.jsonl"
    count = len(calls.read_text().splitlines()) if calls.exists() else 0
    expected = {"unbound": 0, "draft": 1, "preserve": 1}.get(stage, 2)
    assert count == expected
    with ledger(root, evidence) as db:
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 0
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 0
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        reserved = db.execute("select review,settled_at from investigation_call_reservations").fetchall() if "investigation_call_reservations" in tables else []
        assert len(reserved) == expected and all(row[0] == 0 and row[1] is not None for row in reserved)
    assert not (root / ".kuzushi/threat-model.json").exists()
    assert not list((root / ".kuzushi/v3/campaigns").glob("**/queue.json"))
    phase_files = list((root / ".kuzushi").rglob("phase-attempts*.jsonl"))
    if stage not in {"imported", "exact", "restarted"}:
        assert not phase_files
    rows = results(root)
    drafts = [(run, value) for run, value in rows if same_directory(root, value["data"].get("artifactDir"), DRAFT) and "document" in value["data"]]
    if stage != "unbound":
        assert len(drafts) == (1 if stage in {"draft", "preserve"} else 2)
        run, draft = drafts[-1]
        assert not draft["data"]["persisted"] and draft["data"]["modelRef"] is None and draft["data"]["findings"] == []
        (evidence / "draft-replay.txt").write_text("replay " + run)
        path = root / DRAFT / "normalized-threat-model.json"
        if stage == "draft":
            save(evidence, "draft-before", {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        if stage == "preserve":
            assert hashlib.sha256(path.read_bytes()).hexdigest() == json.loads((evidence / "draft-before.json").read_text())["sha256"]
    selected = {"read": DRAFT, "canonical": DRAFT, "partial": ".kuzushi/malformed-stage", "bad": ".kuzushi/bad-primary", "empty": ".kuzushi/empty-stage"}
    if stage in selected:
        matching = [(run, value) for run, value in rows if same_directory(root, value["data"].get("outputDir"), selected[stage]) and "artifactRead" in value["data"]]
        assert matching
        run, value = matching[-1]
        receipt = value["data"]["artifactRead"]
        assert receipt["sourceIdentity"] == "unverified" and receipt["bytesReserved"] <= 32 * 1024 * 1024
        assert value["status"] == ("partial" if stage in {"partial", "empty"} else "failed" if stage == "bad" else "completed")
        if stage == "bad":
            assert receipt["filesUninspected"] == 6 and value["data"]["reason"] == "unusable-artifacts"
        if stage in {"read", "canonical"}:
            assert value["data"]["document"] == drafts[-1][1]["data"]["document"]
        (evidence / (stage + "-replay.txt")).write_text("replay " + run)
    if stage in {"imported", "exact", "restarted"}:
        imported = [value for _, value in rows if value["data"].get("snapshot") and value["data"].get("modelRef")]
        assert len(imported) == 1
        command(evidence, "exact", "threat-model:read", {"threatModelRef": imported[0]["data"]["modelRef"]})
        if stage != "imported":
            assert any(value["data"].get("resolvedFrom") == "exact-context" for _, value in rows)
    save(evidence, stage + "-check", {"interceptedRequests": count, "liveProviderRequests": 0, "rawObservations": 0,
        "decisions": 0, "followupJobs": 0, "activeContextChanged": False, "sourceUnchanged": True,
        "phaseFileCount": len(phase_files), "targetSourceExecuted": False})


def wait(root, evidence, stage):
    deadline = time.monotonic() + 30
    while True:
        try:
            inspect(root, evidence, stage)
            return
        except (AssertionError, FileNotFoundError, json.JSONDecodeError, sqlite3.OperationalError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "prepare":
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    else:
        wait(root, evidence, stage)
