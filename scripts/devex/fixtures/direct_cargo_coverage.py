"""Installed offline audit: separate lockfiles and an explicitly omitted advisory."""
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path

import cargo_audit
from scan_source_settlement import ledger


def prepare(root, evidence, home):
    cargo_audit.seed(root, evidence, home)
    for name in ["a", "b", "a/nested"]:
        (root / name).mkdir(parents=True, exist_ok=True)
        (root / name / "Cargo.lock").write_text(cargo_audit.LOCK)
    scanner = json.loads((evidence / "scanner.json").read_text())
    omitted = evidence / "advisory-db-with-planned-omission"
    shutil.copytree(scanner["advisoryDb"], omitted)
    matches = list(omitted.rglob("RUSTSEC-2020-0071.md"))
    assert len(matches) == 1
    matches[0].unlink()
    cargo_audit.save(evidence, "omitted-database", cargo_audit.hashes(omitted))
    for name, target, database in [("first", "a", scanner["advisoryDb"]),
                                   ("second", "b", scanner["advisoryDb"]),
                                   ("omitted", "a", str(omitted))]:
        command = "run cargo-audit:scan " + json.dumps({"target": target,
            "binary": scanner["binary"], "advisoryDb": database, "offline": True,
            "allowStale": True, "timeoutMs": 30000, "maxLockfileBytes": 1048576})
        (evidence / (name + "-command.txt")).write_text(command)
    cargo_audit.save(evidence, "source-before", cargo_audit.hashes(root))


def inspect(root, evidence, stage):
    assert cargo_audit.hashes(root) == json.loads((evidence / "source-before.json").read_text())
    scanner = json.loads((evidence / "scanner.json").read_text())
    assert cargo_audit.hashes(Path(scanner["advisoryDb"])) == scanner["databaseSourceHashes"]
    omitted = evidence / "advisory-db-with-planned-omission"
    assert cargo_audit.hashes(omitted) == json.loads((evidence / "omitted-database.json").read_text())
    runs = cargo_audit.run_results(root, "cargo-audit:scan")
    expected = {"first": 1, "deferred": 1, "second": 2, "omitted": 3, "restarted": 3}[stage]
    assert len(runs) == expected
    counts = ledger(root)
    assert counts["finding_observations"] == min(expected, 2)
    assert counts["review_decisions"] == (0 if stage == "first" else 1)
    assert counts["findingStatuses"] == ["open"] * min(expected, 2)
    assert counts["investigation_call_reservations"] == counts["investigation_work_attempts"] == 0
    identities, by_selection = {}, {}
    for folder, value in runs:
        assert value["status"] == "completed"
        data = value["data"]
        run = folder.name
        selected = Path(data["target"]).name
        path = selected + "/Cargo.lock"
        stage_receipt = data["phaseStages"][0]
        scan = stage_receipt["scan"]
        assert scan["scope"] == {"target": str(root), "paths": [path], "inspectedFiles": [path]}
        assert scan["plan"] == {"selection": "direct", "engines": ["cargo-audit"]}
        engine = scan["engines"][0]
        assert engine["outcome"] == "complete" and engine["runRef"] == run
        assert "ruleIds" not in engine and "Advisory policy was not recorded" in engine["detail"]
        assert data["sourceCheckCurrent"] is True and data["nativeInspections"][0]["offline"] is True
        observations = json.loads((folder / "findings.json").read_text())
        assert len(observations) == data["count"]
        assert scan["artifactDelta"] == [{"runRef": run, "path": "findings.json"}]
        if observations:
            assert len(observations) == 1 and observations[0]["file_path"] == path
            identities[selected] = observations[0]["fingerprint"]
            if selected == "a":
                (evidence / "original-open.txt").write_text("open generation:" + str(observations[0]["id"]))
        by_selection[(selected, data["count"])] = run
    if expected >= 2:
        assert identities["a"] != identities["b"]
        (evidence / "scope-compare.txt").write_text(f"runs diff {by_selection[('a',1)]} {by_selection[('b',1)]}")
    if expected == 3:
        (evidence / "policy-compare.txt").write_text(f"runs diff {by_selection[('a',1)]} {by_selection[('a',0)]}")
    cargo_audit.save(evidence, stage + "-check", {"counts": counts, "runIds": [p.name for p, _ in runs],
        "separateSelectedIdentities": True, "nestedLockfileExcluded": True, "advisoryPolicyUnknown": True,
        "sourceUnchanged": True, "liveProviderRequests": 0, "targetSourceExecuted": False, "scriptedReviewControls": True})


def wait(root, evidence, stage):
    deadline = time.monotonic() + 30
    while True:
        try:
            inspect(root, evidence, stage)
            return
        except (AssertionError, FileNotFoundError, KeyError, json.JSONDecodeError, sqlite3.OperationalError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "prepare": prepare(root, evidence, Path(sys.argv[4]).resolve())
    else: wait(root, evidence, stage)
