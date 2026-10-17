"""Deterministic owned Git history for source-only native journeys."""
import hashlib
import os
import subprocess
from pathlib import Path

BASELINE = "7cac9e253984e19ccc6aaeee3eb157de049ba667"
LATER = "c557cdbf94b931ecc250b33d33d793f79036a908"
BUNDLE_SHA256 = "e6405083b2cd02c8d78ee852576abb66d9913a5bdb8a5d9b473b921ace4ab5fe"


def git(root, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT="0", GIT_AUTHOR_DATE="2000-01-01T00:00:00+0000",
               GIT_COMMITTER_DATE="2000-01-01T00:00:00+0000")
    command = ["git", "-C", str(root), "-c", "core.hooksPath=" + os.devnull,
               "-c", "commit.gpgSign=false", "-c", "core.autocrlf=false",
               "-c", "user.name=Owned source fixture", "-c", "user.email=fixture@example.invalid", *args]
    return subprocess.run(command, env=env, capture_output=True, text=True,
                          check=True, timeout=20).stdout.strip()


def create(root):
    assert not root.exists(), "Owned fixture repository must be new"
    bundle = Path(__file__).resolve().parents[3] / "tests/fixtures/owned-source-revisions.bundle"
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() == BUNDLE_SHA256
    git(root.parent, "clone", "--quiet", "--branch", "main", "--no-hardlinks", str(bundle), str(root))
    git(root, "branch", "fixture-later", LATER)
    assert set(git(root, "rev-list", "--all").splitlines()) == {BASELINE, LATER}
    assert git(root, "rev-parse", "HEAD") == BASELINE
    assert not git(root, "status", "--porcelain=v1")
    return BASELINE, LATER
