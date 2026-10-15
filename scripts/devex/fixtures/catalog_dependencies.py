"""Inspect declared executable presence without invoking the owned inert file."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from secret_settings import ledger, save

SOURCE = Path("/private/tmp/kuzushi-live-owned-investigation-20261010/target")
SHA = "f29dc288e0660ad20d074fc219c025f98ef7d155"


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def source_files(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in git(root, "ls-files").splitlines() if not name.startswith(".kuzushi/")}


def seed(parent, evidence, home):
    root = parent / "repository"
    assert not root.exists() and home == (evidence / "home").resolve()
    assert git(SOURCE, "branch", "--show-current") == "main" and git(SOURCE, "rev-parse", "HEAD") == SHA
    subprocess.run(["git", "clone", "--local", "--no-hardlinks", "--branch", "main",
                    str(SOURCE), str(root)], capture_output=True, check=True)
    assert git(root, "rev-parse", "HEAD") == SHA
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    binary = evidence / "owned scanner "
    binary.write_text("Owned inert file for presence inspection. Never invoke it.\n")
    binary.chmod(0o600)
    (evidence / "binary-command.txt").write_text("setg binary " + json.dumps(str(binary)))
    save(evidence, "source-before", {"sha":SHA,"files":source_files(root)})


def permission(parent, evidence, executable):
    verify(parent, evidence)
    (evidence / "owned scanner ").chmod(0o700 if executable else 0o600)


def verify(parent, evidence):
    root = parent / "repository"
    before = json.loads((evidence / "source-before.json").read_text())
    assert git(root, "branch", "--show-current") == "main" and git(root, "rev-parse", "HEAD") == SHA
    assert source_files(root) == before["files"] and not git(root, "status", "--porcelain=v1")
    events = [json.loads(line) for line in (root / ".kuzushi/v3/workflow/phase-attempts.jsonl").read_text().splitlines()]
    selected = [row for row in events if row["event"] == "phase_attempt_disposition_recorded"]
    assert len(selected) == 1 and selected[0]["disposition"]["kind"] == "selected"
    assert all(row.get("phase") != "scan" for row in events)
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name:db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
                  for name in ["investigation_call_reservations","investigation_work_attempts","finding_observations","review_decisions"]}
    assert all(count == 0 for count in counts.values()), counts
    runs = [json.loads(path.read_text())["tool"] for path in (root / ".kuzushi/v3/runs").glob("*/run.json")]
    assert "semgrep:scan" not in runs and "sast:scan" not in runs
    save(evidence, "dependency-invariants", {"sha":SHA,"counts":counts,"sourceUnchanged":True,
         "providerRequests":0,"scannerStarted":False,"targetSourceExecuted":False})


if __name__ == "__main__":
    parent, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    evidence.mkdir(parents=True, exist_ok=True)
    mode = sys.argv[3]
    if mode == "seed": seed(parent, evidence, Path(sys.argv[4]).resolve())
    elif mode == "present": permission(parent, evidence, True)
    elif mode == "missing": permission(parent, evidence, False)
    else: verify(parent, evidence)
