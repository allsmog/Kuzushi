"""Synthetic credential metadata only; never sign in, refresh or call a model."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path


def credential_file(evidence, state):
    entry = {"access": "OWNED-NOT-A-REAL-ACCESS-TOKEN", "expires": 1}
    if state in ["refresh", "stored"]:
        entry["refresh"] = "OWNED-NOT-A-REAL-REFRESH-TOKEN"
    if state == "stored":
        entry["expires"] = 4102444800000
    value = {} if state == "missing" else {"openai-codex": entry}
    path = evidence / "owned-credentials.json"
    path.write_text(json.dumps(value) + "\n")
    (evidence / "credential-check.json").write_text(json.dumps({"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "state": state}))


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "main.rs").write_text("// Owned readiness target; never executed.\n")
    (root / "Cargo.toml").write_text('[package]\nname="owned-readiness"\nversion="0.0.0"\nedition="2021"\n')
    credential_file(evidence, "refresh")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model="openai-codex:gpt-5.5"\n[runtime]\napi_key_env="OPENAI_API_KEY"\nthinking_level="medium"\n[runtime.anthropic_oauth]\ncredentials_path=' + json.dumps(str(evidence / "owned-credentials.json")) + '\nallow_env_token=false\n')
    (evidence / "source-before.json").write_text(json.dumps({p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [root / "main.rs", root / "Cargo.toml"]}))


def verify(root, evidence):
    before = json.loads((evidence / "source-before.json").read_text())
    assert all(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest for name, digest in before.items())
    expected = json.loads((evidence / "credential-check.json").read_text())
    assert hashlib.sha256((evidence / "owned-credentials.json").read_bytes()).hexdigest() == expected["sha256"], "TUI mutated credentials"
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    path = root / ".kuzushi/v3/index.sqlite3"
    if path.exists():
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
            tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            for table in ["investigation_call_reservations", "investigation_work_attempts", "finding_observations"]:
                if table in tables:
                    assert db.execute("select count(*) from " + table).fetchone()[0] == 0, table
    for frame in evidence.glob("*.txt"):
        text = frame.read_text()
        assert "OWNED-NOT-A-REAL" not in text, "Credential value leaked in " + frame.name
    (evidence / "no-work-check.json").write_text(json.dumps({"providerRequests": 0, "scanJobsStarted": 0, "sourceUnchanged": True, "credentialFileUnchanged": True, "valuesHidden": True}, indent=2) + "\n")


root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
if stage == "seed":
    seed(root, evidence, Path(sys.argv[4]).resolve())
elif stage in ["refresh", "stored", "invalid", "missing"]:
    credential_file(evidence, stage)
else:
    verify(root, evidence)
