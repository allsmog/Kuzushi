"""Owned divergent Git commits and path-only review. No model or target execution."""
import hashlib
import json
import re
import sys
from pathlib import Path

from owned_source_revisions import git
from secret_settings import ledger, native, save

TOOL = "chrome-rce:review-trigger"


def source_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()
            and not any(part in [".git", ".kuzushi"] for part in path.relative_to(root).parts)}


def command(evidence, name, value):
    (evidence / (name + "-command.txt")).write_text("run " + TOOL + " " + json.dumps(value))


def seed(root, evidence, home):
    assert root.resolve().parent == evidence.resolve() and root.name == "fixture-target"
    assert not (root / "README.md").exists()
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "README.md").write_text("Owned path-history fixture. No vulnerability or source execution.\n")
    git(root, "init", "--quiet")
    git(root, "branch", "-M", "main")
    git(root, "add", "README.md")
    git(root, "commit", "--quiet", "-m", "Record owned path baseline")
    merge_base = git(root, "rev-parse", "HEAD")
    git(root, "switch", "--quiet", "-c", "fixture-base")
    (root / "base-only.md").write_text("Owned base-branch change. Outside the HEAD side of this comparison.\n")
    git(root, "add", "base-only.md")
    git(root, "commit", "--quiet", "-m", "Record owned side branch")
    base_commit = git(root, "rev-parse", "HEAD")
    git(root, "switch", "--quiet", "main")
    for path in ["v8/src/maglev/owned café.cc", "v8/src/compiler/typer.cc", "docs/line\nbreak.md"]:
        source = root / path
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("// Owned inert path marker. Never compiled or executed.\n")
    git(root, "add", "--all")
    git(root, "commit", "--quiet", "-m", "Record owned changed paths")
    head_commit = git(root, "rev-parse", "HEAD")
    with (root / "README.md").open("a") as output:
        output.write("Owned dirty tracked text, outside the commit comparison.\n")
    (root / "untracked-only.md").write_text("Owned untracked text, outside the commit comparison.\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("")
    save(evidence, "source-before", source_hashes(root))
    save(evidence, "commits", {"base": base_commit, "mergeBase": merge_base, "head": head_commit,
        "gitStatus": git(root, "status", "--porcelain=v1", "--untracked-files=all")})
    (evidence / "stage-alias-command.txt").write_text("run sast:scan " + json.dumps({
        "taskMode": "manual", "tasks": ["systems-hunt:systems-context-gatherer"],
        "triage": False, "verify": False, "autoPatch": False}))
    command(evidence, "skipped", {})
    command(evidence, "invalid", {"diffBase": "owned-missing-ref"})
    command(evidence, "review", {"diffBase": "fixture-base"})
    command(evidence, "limited", {"diffBase": "fixture-base", "maxChangedFiles": 1})
    nested = native(root / "v8", evidence, "nested-target", TOOL, {"diffBase": "fixture-base"})
    assert nested["status"] == "completed" and nested["data"]["totalChangedFiles"] == 2
    assert sorted(nested["data"]["changedFiles"]) == ["src/compiler/typer.cc", "src/maglev/owned café.cc"]
    assert nested["data"]["findings"] == [] and nested["data"]["persisted"] is None


def tool_results(root):
    values = []
    for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
        run = json.loads(path.read_text())
        result = path.with_name("result.json")
        if run.get("tool") == TOOL and result.exists():
            values.append((run, json.loads(result.read_text())))
    return sorted(values, key=lambda row: (row[0]["startedAtUnix"], row[0]["runId"]))


def inspect(root, evidence, stage):
    commits = json.loads((evidence / "commits.json").read_text())
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    assert git(root, "rev-parse", "HEAD") == commits["head"]
    assert git(root, "status", "--porcelain=v1", "--untracked-files=all") == commits["gitStatus"]
    rows = tool_results(root)
    if stage == "skipped":
        assert rows[-1][1]["status"] == "skipped" and rows[-1][1]["data"]["findings"] == []
    if stage == "invalid":
        assert rows[-1][1]["status"] == "failed" and "resolve" in json.dumps(rows[-1][1])
    if stage in ["review", "limited", "restarted", "narrow"]:
        completed = [(run, body) for run, body in rows if body.get("data", {}).get("comparison") == "merge-base-to-head"]
        run, result = completed[-1]
        data = result["data"]
        assert data["baseCommit"] == commits["base"] and data["mergeBase"] == commits["mergeBase"]
        assert data["headCommit"] == commits["head"] and data["baseCommit"] != data["mergeBase"]
        assert data["workingTreeExcluded"] and data["findings"] == [] and data["persisted"] is None
        assert data["totalChangedFiles"] == 3
        if stage in ["review", "narrow"]:
            assert result["status"] == "completed" and len(data["reviewHints"]) == 2
            assert data["changedFiles"] == ["docs/line\nbreak.md", "v8/src/compiler/typer.cc", "v8/src/maglev/owned café.cc"]
            (evidence / "replay-command.txt").write_text("replay " + run["runId"])
        else:
            assert result["status"] == "partial" and data["omittedChangedFiles"] == 2
            assert data["reviewHints"] == [] and data["count"] == 0
            (evidence / "limited-replay-command.txt").write_text("replay " + run["runId"])
    if stage == "narrow":
        covered, totals, body = set(), set(), []
        paths = list(evidence.glob("*-comparison-40x12.txt")) + sorted(evidence.glob("*-comparison-reading-*-40x12.txt")) + list(evidence.glob("*-comparison-tail-40x12.txt"))
        for path in paths:
            text = path.read_text()
            start, end, total = map(int, re.search(r"rows (\d+)-(\d+)/(\d+)", text).groups())
            covered.update(range(start, end + 1))
            totals.add(total)
            body.extend(text.splitlines()[2:7])
        assert len(totals) == 1 and covered == set(range(1, next(iter(totals)) + 1))
        compact = "".join("".join(body).split())
        for phrase in ["Actual merge base:", "Compared HEAD:", commits["base"], commits["mergeBase"], commits["head"], "Working-tree, staged and untracked changes are excluded.", "docs/line\\nbreak.md"]:
            assert "".join(phrase.split()) in compact, phrase
        save(evidence, "narrow-reading", {"allRowsReached": True, "rows": next(iter(totals)), "capturePages": len(paths)})
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {table: db.execute("select count(*) from " + table).fetchone()[0] if table in tables else 0
                  for table in ["finding_observations", "review_decisions", "investigation_call_reservations"]}
        assert all(value == 0 for value in counts.values()), counts
    assert not (root / ".kuzushi/v3/campaigns").exists()
    assert not (root / ".kuzushi/threat-models").exists()
    save(evidence, stage + "-check", {"counts": counts, "liveProviderRequests": 0,
        "sourceExecuted": False, "sourceHeadAndStatusUnchanged": True, "newJobs": 0})


if __name__ == "__main__":
    root, evidence = map(Path, sys.argv[1:3])
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]))
    else:
        inspect(root, evidence, sys.argv[3])
