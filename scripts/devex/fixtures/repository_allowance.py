"""Read real refused preparation receipts without provider or target execution."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from secret_settings import ledger, save


def source_hash(root):
    return hashlib.sha256((root / "owned.py").read_bytes()).hexdigest()


def initialize_source(root):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "owned.py").write_text("# Owned metadata. Never executed.\n")
    prefix = ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
              "-c", "core.attributesFile=/dev/null", "-c", "user.name=Owned Fixture",
              "-c", "user.email=fixture@example.invalid"]
    for args in [["init", "-q"], ["add", "-f", "--", "owned.py"],
                 ["commit", "-qm", "fixture source"]]:
        subprocess.run(prefix + args, cwd=root, check=True, capture_output=True, timeout=20)


def seed(root, evidence, home):
    initialize_source(root)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model="openai-codex:gpt-5.5"\n[runtime]\nthinking_level="medium"\n')
    fixture = Path(os.environ["KUZUSHI_NATIVE_BIN"]).with_name("repository-allowance-fixture")
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["KUZUSHI_CODEQL_BIN"] = str(root / "owned.py")
    with (evidence / "fixture-stderr.txt").open("w") as log:
        result = subprocess.run([str(fixture), str(root)], stdout=subprocess.PIPE,
                                stderr=log, text=True, env=env, timeout=30)
    assert result.returncode == 0, (evidence / "fixture-stderr.txt").read_text()
    save(evidence, "fixture-proof", json.loads(result.stdout))
    save(evidence, "source-before", {"sha256": source_hash(root)})
    for state in ["unfunded", "unapproved"]:
        (evidence / (state + "-command.txt")).write_text("replay owned-db-" + state)
    (evidence / "allowance-command.txt").write_text(
        'run campaign:allowance {"investigationId":"owned-db-preparation"}')
    check(root, evidence, "seed")


def check(root, evidence, stage):
    before = json.loads((evidence / "source-before.json").read_text())
    assert source_hash(root) == before["sha256"]
    proof = json.loads((evidence / "fixture-proof.json").read_text())
    assert proof["projectionHealthy"]
    assert proof["queries"] == proof["committedCalls"] == proof["liveProviderRequests"] == 0
    with ledger(root, evidence) as db:
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 0
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions").fetchone()[0])
        assert approval["limits"] == {"maxProviderCalls": 2, "protectedReviewCalls": 1}
    for state, message in [("unfunded", "needs an approved investigation allowance"),
                           ("unapproved", "requires explicit operator authorization")]:
        result = root / ".kuzushi/v3/runs" / ("owned-db-" + state) / "result.json"
        raw = result.read_text()
        assert message in raw
        assert json.loads(raw)["status"] in ["failed", "blocked"]
    assert not (root / ".git/worktrees").exists()
    assert not (root / ".kuzushi/codeql-db").exists()
    assert not (root / ".kuzushi/v3/codeql-db").exists()
    assert not (root / ".kuzushi/v3/campaigns").exists()
    save(evidence, stage + "-check", {"queries": 0, "committedCalls": 0,
        "protectedReviewRemaining": 1, "newJobs": 0, "sourceUnchanged": True,
        "liveProviderRequests": 0, "refusalsRecorded": 2, "executionWorktrees": 0})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        check(root, evidence, stage)
