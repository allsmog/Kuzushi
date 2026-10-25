"""Owned Git-history selection and bounded metadata reads. No source execution."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import source_baselines as base


def source_hash(root):
    return hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest()


def rows(root):
    with sqlite3.connect(root / ".kuzushi/v3/coverage.sqlite3") as db:
        return db.execute("select mode,run_id,revision_sha,ts from scan_baselines order by rowid").fetchall()


def prepare(root, evidence, home):
    assert root.name == "fixture-target" and root.parent == evidence
    base.prepare(root, evidence, home)
    first = base.git(root, "rev-parse", "HEAD")
    (root / "hello.txt").write_text("Owned second source revision. Never executed.\n")
    second = base.commit(root, "Owned second baseline revision")
    with sqlite3.connect(root / ".kuzushi/v3/coverage.sqlite3") as db:
        db.execute("delete from scan_baselines")
        db.executemany("insert into scan_baselines values(?,?,?,?,?,?,?,?)", [
            ("root", "scan", "first", "earlier-record-not-a-scan", first, "main", 0, 100),
            ("root", "scan", "second", "last-recorded-not-a-scan", second, "main", 0, 100),
        ])
    base.save(evidence, "history-state", {"firstSha": first, "secondSha": second,
        "rows": rows(root), "sourceHash": source_hash(root), "configHash": base.load(evidence, "state")["configHash"]})
    verify(root, evidence, "prepared")


def oversized(root, evidence):
    with sqlite3.connect(root / ".kuzushi/v3/coverage.sqlite3") as db:
        db.execute("insert into scan_baselines values(?,?,?,?,?,?,?,?)",
            ("root", "map", "oversized", "x" * (8 * 1024 * 1024 + 1), "owned-metadata", None, 0, 101))
    verify(root, evidence, "oversized")


def restore(root, evidence):
    # Controlled test recovery restores the exact saved small history. Product
    # reads must neither perform this write nor silently truncate the large row.
    with sqlite3.connect(root / ".kuzushi/v3/coverage.sqlite3") as db:
        db.execute("delete from scan_baselines where mode='oversized'")
    verify(root, evidence, "restored")


def verify(root, evidence, stage):
    saved = base.load(evidence, "history-state")
    large = stage in {"oversized", "blocked"}
    if large:
        with sqlite3.connect(root / ".kuzushi/v3/coverage.sqlite3") as db:
            assert db.execute("select count(*) from scan_baselines").fetchone()[0] == 3
            assert db.execute("select length(run_id) from scan_baselines where mode='oversized'").fetchone()[0] == 8 * 1024 * 1024 + 1
    else:
        assert rows(root) == [tuple(row) for row in saved["rows"]]
        result = base.native(root, evidence, "history-" + stage, "coverage:baselines")
        latest = result["data"]["baselines"]
        assert len(latest) == 1 and latest[0]["revisionSha"] == saved["secondSha"], latest
        assert latest[0]["runId"] == "last-recorded-not-a-scan"
        assert result["data"]["scopeCoverageVerified"] is False
        sweep = base.sweep(root, evidence, "history-" + stage)
        assert sweep["data"]["report"]["entries"][0]["baselineSha"] == saved["secondSha"]
        assert sweep["data"]["report"]["entries"][0]["verdict"] == {"kind": "current"}
    assert source_hash(root) == saved["sourceHash"]
    assert base.git(root, "rev-parse", "HEAD") == saved["secondSha"]
    home = Path((evidence / "runtime-home.txt").read_text())
    assert hashlib.sha256((home / ".kuzushi/v3/config.toml").read_bytes()).hexdigest() == saved["configHash"]
    base.no_work(root)
    base.save(evidence, stage + "-history-check", {"historySynthetic": True,
        "sourceUnchanged": True, "providerRequests": 0, "scannerJobs": 0,
        "sourceExecuted": False, "findingFixEstablished": False,
        "expectedStoredRows": 3 if large else 2})


if __name__ == "__main__":
    stage, target, output = sys.argv[1:4]
    root, evidence = Path(target).resolve(), Path(output).resolve()
    if stage == "prepare":
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "oversized":
        oversized(root, evidence)
    elif stage == "restore":
        restore(root, evidence)
    else:
        verify(root, evidence, stage)
