"""Recorded scope reading, metadata failure and recovery. No new discovery work."""
import json
import os
import subprocess
import time
from pathlib import Path
from compact_reader_notice import owned_pane
from investigation_journey import read_native
from rejected_context import execute


def read_scope(root, evidence, plan, name):
    record = plan["scopeStudy"]["cases"][0]["baseInput"]["scanScopeRef"]["proposal"]["recordHash"]
    return read_native(root, evidence, name,
        ["findings", "--scope", "app", "--scope-record", record, "--json"])


def selected_input(root, evidence):
    saved = json.loads((evidence / "scope-input-backup.json").read_text())
    path = (root / saved["path"]).resolve()
    assert path.is_relative_to(root.resolve()), "Fixture input must remain inside its target"
    return path


def wait_frame(root, evidence, kind, expected):
    pane = owned_pane(root)
    deadline = time.monotonic() + 15
    previous = None
    while time.monotonic() < deadline:
        screen = subprocess.check_output(["tmux", "capture-pane", "-p", "-t", pane], text=True)
        rows = screen.splitlines()
        footer = any("/keys all" in row for row in rows[-2:]) if kind == "report" else "REVIEW" in rows[-1]
        if footer and expected in screen and screen == previous:
            dimensions = subprocess.check_output(["tmux", "display-message", "-p", "-t", pane,
                "#{pane_width}x#{pane_height}"], text=True).strip()
            with (evidence / "settled-frames.jsonl").open("a") as output:
                output.write(json.dumps({"kind":kind,"dimensions":dimensions,"footerVisible":True,"stableSamples":2}) + "\n")
            return
        previous = screen
        time.sleep(0.1)
    (evidence / (kind + "-frame-timeout.txt")).write_text(screen)
    raise AssertionError("Owned " + kind + " frame did not finish painting")


def verify(root, evidence, stage, plan):
    if stage == "scope-action-help":
        screen = next(evidence.glob("*-saved-findings-action.txt")).read_text()
        assert "No discovery or model work starts" in " ".join(screen.replace("│", " ").split())
        return
    states = {
        "scope-review-frame": ("review", "scope app · exact record"),
        "scope-other-frame": ("review", "scope other · exact record"),
        "scope-partial-frame": ("review", "partial scope app · 1 unread"),
        "scope-report-frame": ("report", "format "),
    }
    if stage in states:
        return wait_frame(root, evidence, *states[stage])
    if stage == "scope-hide":
        report = read_scope(root, evidence, plan, "scope-before-hide")
        run = report["page"]["scopeFilter"]["matchedRunIds"][0]
        path = root / ".kuzushi/v3/runs" / run / "input.json"
        (evidence / "scope-input-original.bytes").write_bytes(path.read_bytes())
        (evidence / "scope-input-backup.json").write_text(json.dumps({"path": str(path.relative_to(root))}))
        path.write_text("{}")
        return
    if stage == "scope-restore":
        selected_input(root, evidence).write_bytes((evidence / "scope-input-original.bytes").read_bytes())
        return
    report = read_scope(root, evidence, plan, stage + "-cli")
    receipt = report["page"]["scopeFilter"]
    assert report["count"] == report["page"]["total"] == 1
    assert receipt["observedRuns"] == 6 and receipt["unboundRuns"] == 0
    if stage == "scope-hidden":
        assert receipt["matchedRuns"] == 2 and len(receipt["unavailableRuns"]) == 1
        assert selected_input(root, evidence).read_text() == "{}", "Reading cannot repair altered evidence"
    else:
        assert receipt["matchedRuns"] == 3 and receipt["unavailableRuns"] == []
        reference = plan["scopeStudy"]["cases"][0]["baseInput"]["scanScopeRef"]
        assert receipt["references"] == [reference]
        home = Path(os.environ["HOME"])
        tool = execute(root, home, evidence, stage + "-tool", "findings:list", {
            "scope": "app", "scope_record": [reference["proposal"]["recordHash"]]})
        assert tool["findings"] == report["findings"]
        assert tool["page"]["scopeFilter"] == receipt
        empty = read_native(root, evidence, stage + "-unknown", ["findings", "--scope", "unknown-boundary", "--json"])
        assert empty["count"] == 0 and empty["page"]["scopeFilter"]["matchedRuns"] == 0
    (evidence / (stage + "-verified.json")).write_text(json.dumps({
        "receipt":receipt,"findings":1,"newDiscoveryJobs":0,"liveRequests":0}, indent=2) + "\n")
