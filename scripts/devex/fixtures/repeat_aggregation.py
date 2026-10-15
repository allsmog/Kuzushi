"""Three bounded native scans and one unlaunched Review on owned public data."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from secret_settings import ledger, save

CAMPAIGN = "owned-repeat-review"


def native(root, evidence, tool, value, name):
    env = dict(os.environ, HOME=str(evidence / "home"))
    for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KUZUSHI_MODEL", "NODE_OPTIONS"]:
        env.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", tool, "--input", json.dumps(value)], env=env,
        capture_output=True, text=True, timeout=45)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, (name, result.stderr, result.stdout)
    receipt = json.loads(result.stdout)
    save(evidence, name, receipt)
    return receipt["data"]


def seed(root, evidence, home):
    assert home == (evidence / "home").resolve()
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "public-example.env").write_text("# Owned public documentation fixture. No active credential. Never executed.\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    for number in range(1, 4):
        native(root, evidence, "sast:scan", {"taskMode":"manual", "tasks":["secret-scan"],
            "triage":False, "verify":False, "autoPatch":False,
            "secretScanMaxEntries":64, "secretScanMaxTotalBytes":4096,
            "secretScanMaxFileBytes":1024, "secretScanMaxFindings":8}, "pass-" + str(number))
    with ledger(root, evidence) as db:
        rows = db.execute("select run_id,finding_json from finding_observations order by created_seq").fetchall()
        assert len(rows) == 3
        assert len({run for run, _ in rows}) == 3
        expected = [{"run":run,"sources":json.loads(raw)["sources"]} for run, raw in rows]
    save(evidence, "expected-observations", expected)
    save(evidence, "source-before", {"sha256":hashlib.sha256((root / "public-example.env").read_bytes()).hexdigest()})
    native(root, evidence, "campaign:review-study", {"campaignId":CAMPAIGN, "investigationId":CAMPAIGN,
        "reviewInput":{"strategy":"standard", "prefilterThreshold":0,"threatModelRef":None}}, "review-draft")
    verify(root, evidence, "prepared")


def screens(root, evidence):
    captures = [path for path in evidence.glob("*.txt") if path.name[:2].isdigit()]
    first = [path for path in captures if "First observation:" in path.read_text()]
    latest = [path for path in captures if "Latest observation:" in path.read_text()]
    assert first and latest, "Source history must be read in authenticated native captures"
    expected = json.loads((evidence / "expected-observations.json").read_text())
    text = "\n".join(path.read_text() for path in first + latest)
    for row in expected:
        assert row["run"] in text, "Every repeated run remains represented"
    save(evidence, "source-history-screens", {"first": [p.name for p in first], "latest": [p.name for p in latest]})


def verify(root, evidence, stage):
    assert hashlib.sha256((root / "public-example.env").read_bytes()).hexdigest() == json.loads((evidence / "source-before.json").read_text())["sha256"]
    expected = json.loads((evidence / "expected-observations.json").read_text())
    with ledger(root, evidence) as db:
        actual = [{"run":run,"sources":json.loads(raw)["sources"]} for run,raw in
            db.execute("select run_id,finding_json from finding_observations order by created_seq")]
        assert actual == expected
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
            assert table not in tables or db.execute("select count(*) from " + table).fetchone()[0] == 0
    directory = root / ".kuzushi/v3/campaigns" / CAMPAIGN
    plan = json.loads((directory / "plan.json").read_text())
    assert len(plan["jobs"]) == len(plan["findings"]) == 1
    assert plan["findings"][0]["sources"] == expected[-1]["sources"]
    assert not (directory / "queue.json").exists()
    if stage in ["approved", "restarted"]:
        allowance = native(root, evidence, "campaign:allowance", {"investigationId":CAMPAIGN}, stage + "-allowance")["allowance"]
        assert allowance["limits"] == {"maxProviderCalls":2,"protectedReviewCalls":2}
        assert allowance["committedCalls"] == allowance["unresolvedCalls"] == 0
        assert len(allowance["workPlan"]["jobs"]) == 1
    save(evidence, stage + "-verified", {"nativePasses":3,"rawObservations":3,
        "providerRequests":0,"reviewLaunched":False,"sourceExecuted":False,"sourceUnchanged":True})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif sys.argv[3] == "screens":
        screens(root, evidence)
    else:
        verify(root, evidence, sys.argv[3])
