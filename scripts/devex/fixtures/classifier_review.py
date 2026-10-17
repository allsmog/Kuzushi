"""Real public-example observation and bounded intercepted metadata opinions."""
import hashlib
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path

from rejected_context import execute
from secret_settings import ledger, save

MODEL = "openai-codex:gpt-5.5"
INVESTIGATION = "owned-classifier"


def prepare(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    source = root / "owned.env"
    source.write_text("# Owned public example, never an active credential. Never executed.\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("")
    result = execute(root, home, evidence, "source-observation", "secret-scan:scan", {})
    assert len(result["coreFindings"]) == 1
    fingerprint = result["coreFindings"][0]["fingerprint"]
    repo = Path(__file__).resolve().parents[3]
    provider = evidence / "provider.mjs"
    shutil.copyfile(Path(__file__).with_name("classifier_provider.mjs"), provider)
    credentials = home / ".kuzushi/classifier-credentials.json"
    credentials.write_text(json.dumps({"openai-codex": {"access": "offline-classifier-fixture", "expires": 99999999999999}}))
    credentials.chmod(0o600)
    bridge = ["node", "--import", str(provider), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model="' + MODEL + '"\n[runtime]\nthinking_level="medium"\nlanggraph_bridge_command=' + json.dumps(bridge)
        + '\n[runtime.anthropic_oauth]\ncredentials_path=' + json.dumps(str(credentials)) + '\nallow_env_token=false\n')
    approval = {"investigationId": INVESTIGATION, "expectedRevision": 0, "model": MODEL,
                "maxProviderCalls": 4, "protectedReviewCalls": 4,
                "reason": "Four explicit intercepted metadata opinions; no live calls or follow-up jobs"}
    (evidence / "approve-command.txt").write_text("run campaign:approve-allowance " + json.dumps(approval))
    for name, percentile, bound in [("unbound", 0.8, False), ("invalid", 0, True), ("empty", 0.8, True),
                                    ("zero", 0.8, True), ("different", 0.9, True), ("bad", 0.9, True), ("exhausted", 0.8, True)]:
        value = {"findingFingerprint": fingerprint, "targetPercentile": percentile}
        if bound:
            value["allowanceRef"] = {"schemaVersion": 1, "investigationId": INVESTIGATION, "revision": 1, "workId": "score-" + name}
        (evidence / (name + "-command.txt")).write_text("run classifier-gate:score " + json.dumps(value))
    (evidence / "status-command.txt").write_text("run campaign:allowance " + json.dumps({"investigationId": INVESTIGATION}))
    save(evidence, "source-before", {"sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "configSha256": hashlib.sha256(config.read_bytes()).hexdigest(), "home": str(home), "fingerprint": fingerprint})


def phase_files(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (root / ".kuzushi").rglob("phase-attempts*.jsonl")}


def inspect(root, evidence, stage):
    before = json.loads((evidence / "source-before.json").read_text())
    assert hashlib.sha256((root / "owned.env").read_bytes()).hexdigest() == before["sha256"]
    config = Path(before["home"]) / ".kuzushi/v3/config.toml"
    assert hashlib.sha256(config.read_bytes()).hexdigest() == before["configSha256"]
    expected = {"decided": 0, "unbound": 0, "invalid": 0, "empty": 1, "zero": 2,
                "different": 3, "bad": 4, "exhausted": 4, "exported": 4, "restarted": 4}[stage]
    calls = evidence / "classifier-calls.jsonl"
    actual = len(calls.read_text().splitlines()) if calls.exists() else 0
    assert actual == expected
    with ledger(root, evidence) as db:
        decisions = db.execute("select * from review_decisions order by id").fetchall()
        assert len(decisions) == 1
        assert db.execute("select decision_verdict,author from review_decisions").fetchone() == ("rejected_false_positive", "human")
        observation = db.execute("select finding_json from finding_observations").fetchall()
        assert len(observation) == 1
        rows = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        reservations = db.execute("select call_json,review,settled_at from investigation_call_reservations").fetchall() if "investigation_call_reservations" in rows else []
        assert len(reservations) == expected
        for call, review, settled in reservations:
            assert review == 1 and settled is not None and json.loads(call)["work"] == "review"
        states = [json.loads(row[0]) for row in db.execute("select value from kuzushi_state where key like 'classifier.likely_vuln.quantile%'")] if "kuzushi_state" in rows else []
    current = {"decisions": decisions, "observation": observation, "phaseFiles": phase_files(root)}
    if stage == "decided":
        save(evidence, "authority-before", current)
    assert json.loads(json.dumps(current)) == json.loads((evidence / "authority-before.json").read_text())
    expected_states = {} if expected < 2 else {0.8: 1}
    if expected >= 3:
        expected_states[0.9] = 1
    assert {round(value["p"], 3): value["count"] for value in states} == expected_states
    opinions = []
    for path in sorted((root / ".kuzushi/v3/runs").glob("*/result.json")):
        value = json.loads(path.read_text())
        if isinstance(value.get("data"), dict) and value["data"].get("modelOpinionOnly"):
            opinions.append((path.parent, value))
    assert len(opinions) == expected
    for folder, value in opinions:
        assert not value["data"]["findingDecisionChanged"] and not value["data"]["followupStarted"]
        assert value["data"]["sourceTextProvided"] is False
        if value["data"]["score"] is None:
            assert value["status"] == "partial"
            (evidence / "partial-replay.txt").write_text("replay " + folder.name)
        elif value["data"]["score"] == 0:
            assert value["status"] == "completed" and value["data"]["samplesSeen"] == 1
            (evidence / "zero-replay.txt").write_text("replay " + folder.name)
    assert not list((root / ".kuzushi/v3/campaigns").glob("**/queue.json"))
    if stage in {"exported", "restarted"}:
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert report["count"] == 1 and report["findings"][0]["reviewDecision"] == "rejected_false_positive"
    save(evidence, stage + "-check", {"interceptedRequests": expected, "providerRequests": 0,
        "rawObservations": 1, "humanDecisions": 1, "quantileSamples": expected_states,
        "noClassifierPhaseProgress": True, "followupJobs": 0, "sourceAndModelUnchanged": True, "targetSourceExecuted": False})


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
