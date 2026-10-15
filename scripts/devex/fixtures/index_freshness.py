"""Git cache writes versus real staged membership, on owned inert source."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from catalog_dependencies import seed, source_files, SHA
from secret_settings import ledger, save


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True,
        env=dict(os.environ, GIT_OPTIONAL_LOCKS="0")).strip()


def verify(parent, evidence, staged=False):
    root = parent / "repository"
    before = json.loads((evidence / "source-before.json").read_text())
    assert git(root, "rev-parse", "HEAD") == SHA and git(root, "branch", "--show-current") == "main"
    expected = dict(before["files"])
    if staged: expected["added-note.md"] = hashlib.sha256(b"# Owned added scope note\n").hexdigest()
    assert source_files(root) == expected
    assert bool(git(root, "status", "--porcelain=v1")) == staged
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name:db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
                  for name in ["investigation_call_reservations","investigation_work_attempts","finding_observations","review_decisions"]}
    assert all(count == 0 for count in counts.values()), counts
    save(evidence, "source-invariants", {"sha":SHA,"stagedAddition":staged,"counts":counts,
        "providerRequests":0,"sourceExecuted":False})


def cache_write(parent, evidence):
    verify(parent, evidence)
    root = parent / "repository"
    semantic = git(root, "ls-files", "--stage", "-z")
    git(root, "update-index", "--no-untracked-cache")
    before = (root / ".git/index").read_bytes()
    git(root, "update-index", "--untracked-cache")
    after = (root / ".git/index").read_bytes()
    assert before != after and git(root, "ls-files", "--stage", "-z") == semantic
    save(evidence, "cache-write", {"rawIndexChanged":True,"stagedInventoryChanged":False})
    verify(parent, evidence)


def stage(parent, evidence):
    verify(parent, evidence)
    root = parent / "repository"
    (root / "added-note.md").write_bytes(b"# Owned added scope note\n")
    git(root, "add", "added-note.md")
    verify(parent, evidence, True)


def screens(parent, evidence):
    verify(parent, evidence, True)
    paths = list(evidence.glob("*-cache-write-settled.txt"))
    assert len(paths) == 1 and "workspace:stale" not in paths[0].read_text()
    assert "operator source draft" in paths[0].read_text()


if __name__ == "__main__":
    parent, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    evidence.mkdir(parents=True, exist_ok=True)
    mode = sys.argv[3]
    if mode == "seed": seed(parent, evidence, Path(sys.argv[4]).resolve())
    elif mode == "cache": cache_write(parent, evidence)
    elif mode == "stage": stage(parent, evidence)
    elif mode == "screens": screens(parent, evidence)
    else: verify(parent, evidence, True)
