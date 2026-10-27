"""Owned engine-picker readiness fixture. No scanner or model work is approved."""
import json
import hashlib
import subprocess
import sys
from pathlib import Path

from secret_settings import ledger


def source_hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["package.json", "main.rs"]}


def ledger_counts(root, evidence):
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        return {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
                for name in ["finding_observations", "investigation_call_reservations",
                             "investigation_work_attempts", "review_decisions"]}


def seed(root, evidence, home):
    subprocess.run([sys.executable, "-B", str(Path(__file__).with_name("finite_policy.py")),
                    str(root), str(evidence), "seed", str(home)], check=True, timeout=60)
    (home / ".kuzushi/v3/config.toml").write_text('[runtime]\nthinking_level = "low"\n')
    binary = evidence / "owned-presence-only-scanner"
    (evidence / "binary-setting.txt").write_text("setg semgrepBinary " + str(binary))


def verify(root, evidence, stage):
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    counts = ledger_counts(root, evidence)
    assert all(count == 0 for count in counts.values()), counts
    options = evidence / "home/.kuzushi/v3/options.json"
    if stage == "globals":
        (evidence / "original-global-options.json").write_bytes(options.read_bytes())
    assert options.read_bytes() == (evidence / "original-global-options.json").read_bytes()
    binary = evidence / "owned-presence-only-scanner"
    if stage == "nonexecutable":
        binary.write_text("Owned inert presence fixture. Never execute.\n")
        binary.chmod(0o600)
    if stage == "executable":
        binary.chmod(0o700)
    (evidence / ("readiness-" + stage + ".json")).write_text(json.dumps({
        "stage": stage, "sourceUnchanged": True, "globalOptionsPreserved": True,
        "plans": 0, "counts": counts, "liveProviderRequests": 0,
    }, indent=2) + "\n")


if __name__ == "__main__":
    target, artifact = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        seed(target, artifact, Path(sys.argv[4]).resolve())
    else:
        verify(target, artifact, sys.argv[3])
