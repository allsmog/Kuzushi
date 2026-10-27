"""Explicit engine-option cleanup through a finite owned policy investigation."""
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

from secret_settings import ledger

REPO = Path(__file__).resolve().parents[3]
ENGINE_KEYS = ["semgrepConfig", "semgrepJobs", "semgrepTimeoutMs"]


def finite_policy(root, evidence, stage, home=None):
    command = [sys.executable, "-B", str(REPO / "scripts/devex/fixtures/finite_policy.py"),
               str(root), str(evidence), stage]
    if home is not None:
        command.append(str(home))
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (evidence / ("policy-" + stage + ".stdout.txt")).write_text(result.stdout)
    (evidence / ("policy-" + stage + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, result.stderr


def seed(root, evidence, home):
    finite_policy(root, evidence, "seed", home)
    rules = evidence / "owned-old-rules.yml"
    rules.write_text("rules:\n  - id: owned-inert-marker\n    pattern: UNUSED_OWNED_MARKER\n    message: Owned inert fixture\n    languages: [python]\n    severity: INFO\n")
    (evidence / "old-rule-setting.txt").write_text("setg semgrepConfig " + json.dumps([str(rules)]))


def saved_options(evidence):
    path = evidence / "home/.kuzushi/v3/options.json"
    return path, json.loads(path.read_text())


def remember_globals(evidence):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            path, options = saved_options(evidence)
            values = options["bindings"]["global/tool/sast:scan"]
            if values.get("semgrepJobs") == 1 and values.get("semgrepTimeoutMs") == 60000:
                assert values["semgrepConfig"] == [str(evidence / "owned-old-rules.yml")]
                (evidence / "original-global-options.json").write_bytes(path.read_bytes())
                return
        except (KeyError, FileNotFoundError):
            pass
        time.sleep(0.1)
    raise AssertionError("Original engine settings were not persisted")


def verify(root, evidence, stage):
    if stage == "globals":
        remember_globals(evidence)
    path, _ = saved_options(evidence)
    assert path.read_bytes() == (evidence / "original-global-options.json").read_bytes()
    before = json.loads((evidence / "source-before.json").read_text())
    assert {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in before} == before
    if stage in ["draft", "completed", "exported", "restarted"]:
        finite_policy(root, evidence, stage)
        plans = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
        plan = next(p for p in plans if p["kind"] == "scan-batch")
        for value in [plan["baseInput"], *[job["input"] for job in plan["jobs"]]]:
            assert not set(ENGINE_KEYS).intersection(value), "Global engine options re-entered the local plan"
    else:
        with ledger(root, evidence) as db:
            tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            for table in ["finding_observations", "investigation_call_reservations", "investigation_work_attempts"]:
                if table in tables:
                    assert db.execute("select count(*) from " + table).fetchone()[0] == 0
        assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    (evidence / ("engine-options-" + stage + ".json")).write_text(json.dumps({
        "stage": stage, "globalOptionsPreserved": True, "sourceUnchanged": True,
        "liveProviderRequests": 0, "targetSourceExecuted": False,
    }, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, sys.argv[3])
