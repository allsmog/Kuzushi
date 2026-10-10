"""Read an actual frozen plan over owned comments, without approving or running it."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

CAMPAIGN = "owned-settings-reader"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    source = root / "owned.rs"
    source.write_text("// Owned presentation fixture. No executable source.\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    value = {"campaignId": CAMPAIGN, "scanInput": {
        "taskMode": "manual", "tasks": ["secret-scan"],
        "threatModelRef": None, "scanContextRef": None}}
    env = {key: value for key, value in os.environ.items() if key not in [
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "KUZUSHI_MODEL",
        "KUZUSHI_LANGGRAPH_BRIDGE", "NODE_OPTIONS", "KUZUSHI_AGENT_MCPS"]}
    env["HOME"] = str(home)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", "campaign:study", "--input", json.dumps(value)], env=env,
        capture_output=True, text=True, timeout=35)
    (evidence / "prepared-plan.stdout.json").write_text(result.stdout)
    (evidence / "prepared-plan.stderr.txt").write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)["data"]
    assert receipt["jobCount"] == 3
    plan = Path(receipt["planPath"])
    if not plan.is_absolute():
        plan = root / plan
    (evidence / "reader-before.json").write_text(json.dumps({
        "source": str(source), "sourceHash": digest(source), "config": str(config),
        "configHash": digest(config), "plan": str(plan), "planHash": digest(plan),
        "input": receipt["scanInput"], "jobCount": receipt["jobCount"],
    }, indent=2) + "\n")
    inspect(root, evidence, "seeded")


def no_work(root):
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    db = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_allowance_revisions", "investigation_call_reservations",
                "investigation_work_attempts", "finding_observations", "finding_decisions"]:
            if table in tables:
                assert connection.execute("select count(*) from " + table).fetchone()[0] == 0, table


def setting_body_text(paths):
    body = []
    for path in sorted(paths, key=lambda path: int(path.stem.rsplit("-", 1)[1])):
        page = [line[2:-1].rstrip() for line in path.read_text().splitlines()[3:9]]
        overlap = 0
        for count in range(1, min(len(body), len(page)) + 1):
            if body[-count:] == page[:count]:
                overlap = count
        body.extend(page[overlap:])
    return "".join("".join(body).split())


def inspect(root, evidence, label):
    before = json.loads((evidence / "reader-before.json").read_text())
    for name in ["source", "config", "plan"]:
        assert digest(Path(before[name])) == before[name + "Hash"], name + " changed"
    no_work(root)
    result = {"fixedJobs": before["jobCount"], "planUnchanged": True,
        "sourceUnchanged": True, "configUnchanged": True, "providerRequests": 0,
        "scannerJobs": 0, "approvals": 0, "syntheticFindings": False}
    if label == "paged":
        settings = sorted(evidence.glob("*settings-page-40x12-*.txt"))
        raw = sorted(evidence.glob("*raw-page-40x12-*.txt"))
        setting_text = "".join("".join(path.read_text().split()) for path in settings)
        raw_text = "".join("".join(path.read_text().split()) for path in raw)
        for key in before["input"]:
            assert "(" + key + ")" in setting_text, "Unreadable setting: " + key
            assert json.dumps(key) in raw_text, "Unreadable JSON key: " + key
        body = setting_body_text(settings)
        for key, value in before["input"].items():
            exact_value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
            expected = "".join(("(" + key + ")Value:" + exact_value).split())
            assert expected in body, "Recorded value missing or changed: " + key
        assert "Thisworkflowoffersnotargetexecution,reproducerorpatchactions" in body
        assert "Generatepatchesforverifiedtruepositives" not in body
        assert "ExecutegeneratedPoCs" not in body
        assert len({path.read_text() for path in settings}) > 3
        assert len({path.read_text() for path in raw}) > 3
        before_json = next(evidence.glob("*settings-before-json-40x12.txt")).read_text()
        returned = next(evidence.glob("*settings-retained-position-40x12.txt")).read_text()
        assert returned == before_json, "Switching JSON moved the Settings reading position"
        result.update({"settingsFieldsRead": len(before["input"]),
            "jsonFieldsRead": len(before["input"]), "settingsCaptures": len(settings),
            "jsonCaptures": len(raw)})
    (evidence / (label + "-check.json")).write_text(json.dumps(result, indent=2) + "\n")


def main():
    root, evidence, stage = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]))
    else:
        inspect(root, evidence, stage)


if __name__ == "__main__":
    main()
