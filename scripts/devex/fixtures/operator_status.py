"""Owned source metadata and a real, runtime-free repository index."""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import sbom_spdx
from sbom_shapes import assert_no_investigation
from inventory_input import owned_pane


def git(root, *arguments):
    environment = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    return subprocess.run(["git", "-C", str(root), *arguments], env=environment,
                          check=True, text=True, capture_output=True).stdout.strip()


def prepare(root, evidence):
    root.mkdir(parents=True, exist_ok=True)
    sbom_spdx.prepare(root, evidence)
    git(root, "init", "--quiet", "--initial-branch=main")
    git(root, "add", "--", *sbom_spdx.NAMES)
    sbom_spdx.save(evidence, "index-before", git(root, "ls-files", "--stage"))


def inspect(root, evidence, stage):
    assert sbom_spdx.sources(root) == json.loads((evidence / "source.json").read_text())
    assert git(root, "ls-files", "--stage") == json.loads((evidence / "index-before.json").read_text())
    assert git(root, "rev-list", "--all", "--count") == "0"
    assert_no_investigation(root)
    receipts = {path.parent.name: json.loads(path.read_text())
                for path in (root / ".kuzushi/v3/runs").glob("*/result.json")}
    assert len(receipts) == 1, receipts
    result = next(iter(receipts.values()))
    assert result["status"] == "completed", result
    snapshot_path = root / ".kuzushi/context-snapshot.json"
    snapshot = json.loads(snapshot_path.read_text())
    assert snapshot["filesIndexed"] == len(sbom_spdx.NAMES)
    inspection = snapshot["repositoryInventory"]["inspection"]
    assert inspection["enumeration"] == "git-index", inspection
    assert set(inspection["files"]) == set(sbom_spdx.NAMES), inspection
    assert not inspection["truncated_files"], inspection
    saved = evidence / "built-snapshot.bin"
    if stage == "built":
        saved.write_bytes(snapshot_path.read_bytes())
    else:
        assert snapshot_path.read_bytes() == saved.read_bytes()
        assert sorted(receipts) == json.loads((evidence / "built-check.json").read_text())["runs"]
    sbom_spdx.save(evidence, stage + "-check", {
        "runs": sorted(receipts), "indexedFiles": len(sbom_spdx.NAMES),
        "sourceUnchanged": True, "indexUnchanged": True, "commitsCreated": 0,
        "providerRequests": 0, "targetExecuted": False, "investigationJobs": 0})


def inspect_source_bindings(root, evidence, home, stage):
    run_path = next((root / ".kuzushi/v3/runs").glob("*/run.json"))
    run = json.loads(run_path.read_text())
    result = json.loads(run_path.with_name("result.json").read_text())
    canonical = str(root)
    assert run["target"] == result["data"]["root"] == canonical
    assert result["output"].count(canonical) == 2
    sessions = list((home / ".kuzushi/v3/sessions").rglob("*.jsonl"))
    assert len(sessions) == (1 if stage == "built" else 2), sessions
    records = [json.loads(line) for path in sessions for line in path.read_text().splitlines()]
    metadata = [row["payload"] for row in records if row["type"] == "session_meta"]
    assert len(metadata) == len(sessions)
    assert all(row["initialTarget"] == canonical for row in metadata)
    logs = [row["payload"] for row in records if row["type"] == "log_emitted"]
    startup = [row["message"] for row in logs if row["level"] == "startup"]
    launch = [row["message"] for row in logs if row["level"] == "tool"
              and row["message"].startswith("running context:build ")]
    assert len(startup) == len(sessions) and len(launch) == 1
    assert all(message.endswith("target ./" + root.name) for message in startup)
    assert " · target ./" + root.name + " · run " + run["runId"] in launch[0]
    assert all(canonical not in message for message in startup + launch)
    raw_results = [row["message"] for row in logs if row["level"] == "result"]
    assert raw_results == [result["output"]], raw_results
    sbom_spdx.save(evidence, stage + "-source-bindings", {
        "canonicalTarget": canonical, "runId": run["runId"], "sessions": len(sessions),
        "compactStartupMessages": len(startup), "compactLaunchMessages": len(launch),
        "rawResultUnchanged": True, "canonicalResultPathOccurrences": 2,
        "providerRequests": 0, "sourceExecuted": False})


def reader_rows(evidence):
    captures = sorted(evidence.glob("*literal-reader*40x12.txt"))
    assert len(captures) == 7, captures
    rows = {}
    for path in captures:
        lines = path.read_text().splitlines()
        assert "READ TRANSCRIPT" in lines[0], path
        inner = [line[1:-1] for line in lines[1:-1]]
        index, match = next((index, re.match(r"\s*rows (\d+)-(\d+)/(\d+)", line))
                            for index, line in enumerate(inner) if re.match(r"\s*rows \d+-", line))
        first, last = int(match[1]), int(match[2])
        body = inner[index + 1:index + 2 + last - first]
        assert len(body) == last - first + 1, path
        for number, line in enumerate(body, first):
            assert number not in rows or rows[number] == line, (path, number)
            rows[number] = line
    return rows, captures


def matches_printed_rows(expected, fragments):
    positions = {0}
    for fragment in fragments:
        following = set()
        for offset in positions:
            maximum = min(len(fragment), len(expected) - offset)
            for count in range(maximum + 1):
                if fragment[:count] == expected[offset:offset + count] and not fragment[count:].strip():
                    following.add(offset + count)
        if len(expected) in following:
            return True
        positions = following
    return False


def inspect_reader(root, evidence):
    rows, captures = reader_rows(evidence)
    prefix = re.compile(r" \d{2}:\d{2}:\d{2}Z ◆ result (.*)")
    first, match = next((number, prefix.match(line))
                        for number, line in sorted(rows.items()) if prefix.match(line))
    fragments = [match[1]]
    for number in range(first + 1, max(rows) + 1):
        assert number in rows, number
        line = rows[number]
        continuation = re.match(r"(?: \d{2}:\d{2}:\d{2}Z)? … (.*)", line)
        if continuation is None:
            break
        fragments.append(continuation[1])
    result_path = next((root / ".kuzushi/v3/runs").glob("*/result.json"))
    output = json.loads(result_path.read_text())["output"]
    assert matches_printed_rows(output.replace("\n", ""), fragments), fragments
    sbom_spdx.save(evidence, "reader-check", {
        "captures": [path.name for path in captures], "capturedRows": len(rows),
        "completeLiteralResultReachable": True, "onlyTrailingCellPaddingIgnored": True,
        "repositoryName": root.name, "providerRequests": 0})


def wait_for_draft_viewport(root, evidence, dimensions):
    assert re.fullmatch(r"[1-9][0-9]*x[1-9][0-9]*", dimensions), dimensions
    pane = owned_pane(root.parent)
    deadline = time.monotonic() + 10
    previous = None
    while time.monotonic() < deadline:
        size = subprocess.check_output(["tmux", "display-message", "-p", "-t", pane,
                                       "#{pane_width}x#{pane_height}"], text=True).strip()
        rows = subprocess.check_output(["tmux", "capture-pane", "-p", "-t", pane], text=True).splitlines()
        bottom = rows[-1] if rows else ""
        ready = size == dimensions and bottom.lstrip().startswith("kz>") and "status-copy draft" in bottom
        if ready and previous == bottom:
            sbom_spdx.save(evidence, "draft-" + dimensions, {
                "pane": pane, "dimensions": size, "draftAtTerminalBottom": True,
                "consecutiveObservations": 2, "providerRequests": 0})
            return
        previous = bottom if ready else None
        time.sleep(0.05)
    raise AssertionError("Draft did not settle at terminal bottom: " + dimensions)


if __name__ == "__main__":
    target, artifacts = [Path(value).resolve() for value in sys.argv[1:3]]
    action = sys.argv[3]
    if action == "prepare":
        prepare(target, artifacts)
    elif action == "reader":
        inspect_reader(target, artifacts)
    elif action == "viewport":
        wait_for_draft_viewport(target, artifacts, sys.argv[4])
    else:
        inspect(target, artifacts, action)
        if len(sys.argv) > 4:
            inspect_source_bindings(target, artifacts, Path(sys.argv[4]).resolve(), action)
