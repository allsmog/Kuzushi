"""Actual prepared triage with a labeled runtime stand-in, then native readers."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from secret_settings import ledger


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def seed(root, evidence, home):
    assert home == (evidence / "home").resolve()
    assert not (evidence / "source-before.json").exists()
    env = dict(os.environ, KUZUSHI_TRIAGE_FIXTURE_OUT=str(root))
    result = subprocess.run([os.environ["KUZUSHI_TRIAGE_TEST_BIN"], "--exact",
        "modules::registry::triage_contract_tests::prepare_native_triage_source_fixture",
        "--nocapture"], env=env, text=True, capture_output=True, timeout=45, check=True)
    (evidence / "preparation.log").write_text(result.stdout + result.stderr)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    save(evidence, "source-before", {"sha256": hashlib.sha256((root / "note.md").read_bytes()).hexdigest()})
    with ledger(root, evidence) as db:
        ids = {json.loads(row[0])["scan_id"]: json.loads(row[0])["id"]
            for row in db.execute("select finding_json from finding_observations")}
    for name in ["first", "second"]:
        (evidence / ("open-" + name + ".txt")).write_text("open generation:" + str(ids[name]))
    save(evidence, "generation-references", ids)
    verify(root, evidence, "prepared")


def verify(root, evidence, stage):
    receipt = json.loads((root / ".kuzushi/triage-audit-fixture.json").read_text())
    assert receipt["syntheticOutcomes"] and receipt["liveProviderRequests"] == 0
    assert receipt["runtimeInvocations"] == 2 and not receipt["sourceExecuted"]
    first, second = receipt["first"], receipt["second"]
    assert first["status"] == second["status"] == "completed"
    assert first["data"]["triaged"] == second["data"]["triaged"] == 1
    assert first["data"]["snapshotHash"] != second["data"]["snapshotHash"]
    assert hashlib.sha256((root / "note.md").read_bytes()).hexdigest() == json.loads((evidence / "source-before.json").read_text())["sha256"]
    results = list((root / ".kuzushi/v3/runs").glob("*/result.json"))
    assert len(results) == 4, "Reading must not start another tool"
    with ledger(root, evidence) as db:
        observations = db.execute("select count(*) from finding_observations").fetchone()[0]
        decisions = db.execute("select count(*) from review_decisions").fetchone()[0]
        assert observations == 2
        assert decisions == (3 if stage in ["exported", "restarted"] else 2)
    if stage in ["exported", "restarted"]:
        report = json.loads((root / ".kuzushi/reports/report.sarif").read_text())
        assert len(report["runs"][0]["results"]) == 1
        assert "Owned review remains uncertain" in json.dumps(report)
    save(evidence, stage + "-verified", {"syntheticOutcomes": True, "runtimeInvocations": 2,
        "providerRequests": 0, "sourceExecuted": False, "sourceUnchanged": True,
        "observations": observations, "decisions": decisions, "resultArtifacts": len(results)})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, stage)
