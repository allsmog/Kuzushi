"""Installed offline audit, controlled source changes and preserved failure causes."""
import json
import sqlite3
import sys
import time
from pathlib import Path

import cargo_audit
from secret_settings import ledger

CAUSE = "Owned audit adapter stopped for this fixture"


def save(evidence, name, value):
    cargo_audit.save(evidence, name, value)


def prepare(root, evidence, home):
    cargo_audit.seed(root, evidence, home)
    (root / "Cargo.lock").write_text(cargo_audit.LOCK)
    scanner = json.loads((evidence / "scanner.json").read_text())
    wrapper = evidence / "owned-audit-adapter.py"
    wrapper.write_text(f"#!{sys.executable}\n" +
        "import os,sys,time\nfrom pathlib import Path\n" +
        f"evidence=Path({str(evidence)!r})\n" +
        "mode=(evidence/'mode.txt').read_text().strip()\n"
        "if '--version' not in sys.argv and mode in ['drift','fail-drift']:\n"
        " (evidence/'entered').write_text('analysis started after source capture')\n"
        " deadline=time.monotonic()+25\n"
        " while not (evidence/'release').exists():\n"
        "  if time.monotonic()>=deadline: raise SystemExit('Owned adapter wait timed out')\n"
        "  time.sleep(0.02)\n"
        f" if mode=='fail-drift': sys.stderr.write({CAUSE!r}+'\\n'); raise SystemExit(2)\n" +
        f"os.execv({scanner['binary']!r},[{scanner['binary']!r}]+sys.argv[1:])\n")
    wrapper.chmod(0o700)
    (evidence / "mode.txt").write_text("stable")
    command = "run cargo-audit:scan " + json.dumps({"binary":str(wrapper),
        "advisoryDb":scanner["advisoryDb"],"offline":True,"allowStale":True,
        "timeoutMs":30000,"maxLockfileBytes":1048576})
    (evidence / "scan-command.txt").write_text(command)
    save(evidence, "expected-source", cargo_audit.hashes(root))


def prepare_change(evidence, mode):
    for name in ["entered", "release"]:
        (evidence / name).unlink(missing_ok=True)
    (evidence / "mode.txt").write_text(mode)


def release_change(root, evidence):
    deadline = time.monotonic() + 20
    while not (evidence / "entered").is_file():
        assert time.monotonic() < deadline, "Owned audit adapter did not start"
        time.sleep(0.05)
    mode = (evidence / "mode.txt").read_text()
    (root / "README.md").write_text("Planned inert operator edit during " + mode + ".\n")
    save(evidence, "expected-source", cargo_audit.hashes(root))
    (evidence / "release").write_text("continue this local request")


def inspect(root, evidence, stage):
    assert cargo_audit.hashes(root) == json.loads((evidence / "expected-source.json").read_text())
    scanner = json.loads((evidence / "scanner.json").read_text())
    assert cargo_audit.hashes(Path(scanner["advisoryDb"])) == scanner["databaseSourceHashes"]
    runs = cargo_audit.run_results(root, "cargo-audit:scan")
    statuses = [value["status"] for _, value in runs]
    expected = {"baseline":(1,0,0,1,0), "deferred":(1,0,0,1,1), "partial":(1,1,0,2,1),
        "failed":(1,1,1,2,1), "report":(1,1,1,2,1), "complete":(2,1,1,3,1), "restarted":(2,1,1,3,1)}[stage]
    counts = cargo_audit.counts(root, evidence)
    assert (statuses.count("completed"),statuses.count("partial"),statuses.count("failed"),
        counts["finding_observations"],counts["review_decisions"]) == expected
    assert counts["investigation_call_reservations"] == counts["investigation_work_attempts"] == 0
    with ledger(root, evidence) as db:
        run_statuses = dict(db.execute("select run_id,status from run_states"))
        assert [row[0] for row in db.execute("select current_status from stable_findings")] == ["open"]
    for folder, value in runs:
        assert json.loads((folder / "run.json").read_text())["status"] == value["status"]
        data = value["data"]
        assert len(data["treeHash"]) == len(data["snapshotHash"]) == 64
        assert data["sourceCheckCurrent"] == (value["status"] == "completed")
        assert data["nativeInspections"][0]["offline"] is True
        if value["status"] == "failed":
            assert "failed" in value["summary"].lower()
            assert CAUSE in value["output"] and CAUSE in json.dumps(value["errors"])
            assert "source changed" in json.dumps(value["warnings"]).lower()
            assert not data.get("persisted")
        else:
            assert data["count"] == 1 and data["persisted"]["runId"] == folder.name
            assert run_statuses[folder.name] == value["status"]
    save(evidence, stage + "-check", {"statuses":statuses,"runStatuses":run_statuses,
        "counts":counts,"installedOfflineScanner":True,"controlledAdapterFailure":True,
        "scriptedReviewControls":True,"liveProviderRequests":0,"targetSourceExecuted":False})


def wait_for_inspection(root, evidence, stage):
    deadline = time.monotonic() + 25
    while True:
        try:
            inspect(root, evidence, stage)
            return
        except (AssertionError,FileNotFoundError,json.JSONDecodeError,sqlite3.OperationalError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


if __name__ == "__main__":
    root,evidence,stage = Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
    if stage == "prepare": prepare(root,evidence,Path(sys.argv[4]).resolve())
    elif stage == "prepare-drift": prepare_change(evidence,"drift")
    elif stage == "prepare-failure": prepare_change(evidence,"fail-drift")
    elif stage == "release": release_change(root,evidence)
    elif stage == "stable": (evidence / "mode.txt").write_text("stable")
    else: wait_for_inspection(root,evidence,stage)
