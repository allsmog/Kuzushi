"""Render a genuine refused inherited dispatch. No provider or target execution."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from secret_settings import ledger, save


def source_hashes(root):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.iterdir() if path.is_file() and not path.name.startswith(".")}


def seed(root, evidence, home):
    source = root / "main.rs"
    source.write_text("// Owned context marker. Never executed.\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model="openai-codex:gpt-5.5"\n[runtime]\nthinking_level="medium"\n')
    fixture = Path(os.environ["KUZUSHI_NATIVE_BIN"]).with_name("allowance-inheritance-fixture")
    result = subprocess.run([str(fixture), str(root)], capture_output=True, text=True, timeout=30)
    (evidence / "fixture-stderr.txt").write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    proof = json.loads(result.stdout)
    save(evidence, "fixture-proof", proof)
    save(evidence, "source-before", source_hashes(root))
    (evidence / "replay-command.txt").write_text("replay " + proof["runId"])
    (evidence / "allowance-command.txt").write_text('run campaign:allowance {"investigationId":"owned-inherited"}')
    check(root, evidence, "seed")


def check(root, evidence, stage):
    before = json.loads((evidence / "source-before.json").read_text())
    assert source_hashes(root) == before
    proof = json.loads((evidence / "fixture-proof.json").read_text())
    assert proof["projectionHealthy"]
    assert proof["queries"] == proof["committedCalls"] == proof["liveProviderRequests"] == 0
    with ledger(root, evidence) as db:
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 0
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["finding_observations", "review_decisions"]:
            assert table not in tables or db.execute("select count(*) from " + table).fetchone()[0] == 0
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions").fetchone()[0])
        assert approval["limits"] == {"maxProviderCalls": 1, "protectedReviewCalls": 1}
    run = root / ".kuzushi/v3/runs" / proof["runId"]
    saved = json.loads((run / "result.json").read_text())
    assert "parent Review allowance" in (run / "result.json").read_text()
    assert saved["status"] in ["failed", "blocked"]
    assert not (root / ".kuzushi/v3/campaigns").exists()
    save(evidence, stage + "-check", {"queries": 0, "committedCalls": 0,
        "protectedReviewRemaining": 1, "newJobs": 0, "sourceUnchanged": True,
        "liveProviderRequests": 0, "refusalRecorded": True})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        check(root, evidence, stage)
