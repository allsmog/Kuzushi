"""Wait for an owned investigation's footer, including the shared call counter."""
import json
import re
import subprocess
import sys
import time
from pathlib import Path

from compact_reader_notice import owned_pane


def active_work(root, evidence):
    import os
    import investigation_cancellation as fixture
    before = json.loads((evidence / "before-stop.json").read_text())
    plan = fixture.scan_plan(root)
    control = json.loads((root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "dispatcher-control.json").read_text())
    assert control["pid"] == before["control"]["pid"], "Observe the original dispatcher"
    fixture.live(control["pid"], os.environ["KUZUSHI_NATIVE_BIN"], root, plan["campaignId"])
    fixture.live(before["admittedRequest"]["bridgePid"], evidence / "provider.mjs")
    jobs = fixture.queue(root, plan)
    assert {key: value["state"] for key, value in jobs.items()} == {key: value["state"] for key, value in before["jobs"].items()}
    assert len(fixture.investigation.calls(evidence)) == 3
    assert fixture.investigation.accounting(root, plan["investigationId"])["reservations"] == [3, 1, 0]
    (evidence / "active-footer-verified.json").write_text(json.dumps({"sameDispatcher": True,
        "sameAdmittedBridge": True, "newProviderRequests": 0, "fixedJobs": len(jobs), "calls": 3,
        "unsettled": 1, "queueStatesUnchanged": True}) + "\n")


def controls_visible(rows, kind):
    if kind == "report":
        return any("/keys all" in row for row in rows[-2:])
    return bool(rows) and any(phase in rows[-1] for phase in ["MAP", "SCAN", "REVIEW"])


def verify(root, evidence, count, kind):
    assert root.name == "fixture-target" and root.parent == evidence
    assert re.fullmatch(r"[0-9]+/[0-9]+", count) and kind in {"workbench", "report"}
    pane = owned_pane(root)
    deadline = time.monotonic() + 20
    previous = None
    while time.monotonic() < deadline:
        screen = subprocess.check_output(["tmux", "capture-pane", "-p", "-t", pane], text=True)
        rows = screen.splitlines()
        footer = next((row for row in rows[-12:] if "⛭" in row), "")
        if controls_visible(rows, kind) and "calls " + count in footer and screen == previous:
            for diagnostic in [" route", "notify:", "focus unknown"]:
                assert diagnostic not in footer, "Diagnostic crowded the investigation footer: " + footer
            dimensions = subprocess.check_output(["tmux", "display-message", "-p", "-t", pane,
                "#{pane_width}x#{pane_height}"], text=True).strip()
            with (evidence / "investigation-footer-frames.jsonl").open("a") as output:
                output.write(json.dumps({"kind": kind, "calls": count, "dimensions": dimensions,
                    "footer": footer, "controlsVisible": True, "stableSamples": 2}) + "\n")
            return
        previous = screen
        time.sleep(0.1)
    (evidence / (kind + "-footer-timeout.txt")).write_text(screen)
    raise AssertionError("Owned investigation footer did not settle with calls " + count)


if __name__ == "__main__":
    root, evidence = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    assert root.name == "fixture-target" and root.parent == evidence
    if sys.argv[3] == "active":
        active_work(root, evidence)
    else:
        verify(root, evidence, sys.argv[3], sys.argv[4])
