"""Owned prepared-study recovery and typing during real finite native work."""
import hashlib
import json
import os
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

import context_checkpoint
import inventory_input
import shared_monorepo
import study_settings_checkpoint
from installed_scope_study import current_counts, save


def plans(root):
    return [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")
            if json.loads(path.read_text()).get("kind") == "scope-study"]


def invariant(root, evidence):
    assert shared_monorepo.hashes(root) == json.loads((evidence / "source-before.json").read_text())
    assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text()).get("active") is None
    assert current_counts(root, evidence).get("investigation_call_reservations") in [None, 0]


def crash(root, evidence, home):
    invariant(root, evidence)
    work = plans(root)
    assert len(work) == 1 and len(work[0]["jobs"]) == 9
    records = study_settings_checkpoint.records(home, root)
    assert len(records) == 1, "Prepared unapproved choices must remain checkpointed"
    path, record = records[0]
    snapshot = record["snapshot"]
    assert snapshot["investigationId"] == work[0]["investigationId"]
    assert snapshot["maxProviderCalls"] == snapshot["protectedReviewCalls"] == 1
    assert len(snapshot["scope"]["cases"]) == 3
    assert all(count in [None, 0] for count in current_counts(root, evidence).values())
    save(evidence, "original-prepared-plan", work[0])
    context_checkpoint.crash_owned_shell(root, evidence, home, path, record)


def inspect(root, evidence, stage):
    invariant(root, evidence)
    original = json.loads((evidence / "original-prepared-plan.json").read_text())
    work = plans(root)
    expected = 1 if stage == "restored" else 2
    assert len(work) == expected
    assert next(p for p in work if p["campaignId"] == original["campaignId"]) == original
    for plan in work:
        assert plan["investigationId"] == original["investigationId"]
        assert plan["scopeStudy"]["proposalRef"] == original["scopeStudy"]["proposalRef"]
        assert len(plan["jobs"]) == 9 and plan["workers"] == 1
        assert not (root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json").exists()
    assert all(count in [None, 0] for count in current_counts(root, evidence).values())
    if stage == "prepared":
        replacement = next(p for p in work if p["campaignId"] != original["campaignId"])
        save(evidence, "replacement-plan", replacement)
    save(evidence, stage + "-recovery-check", {"plans":expected,"providerCalls":0,
        "sourceExecuted":False,"originalPlanUnchanged":True,"jobsStarted":0})


def live_dispatcher(root, evidence, plan_file="replacement-plan.json"):
    source = next(evidence.glob("*running.txt"))
    pid = int(re.search(r"dispatcher pid (\d+)", source.read_text()).group(1))
    os.kill(pid, 0)
    command = subprocess.check_output(["ps", "-p", str(pid), "-o", "command="], text=True)
    assert str(root) in command or str(root.resolve()) in command
    plan = json.loads((evidence / plan_file).read_text())
    assert plan["campaignId"] in command
    proofs = [json.loads(p.read_text()) for p in evidence.glob("*.provenance.json")]
    executable = Path(proofs[-1]["native_resolved_path"]).resolve()
    images = subprocess.check_output(["lsof", "-a", "-p", str(pid), "-d", "txt", "-Fn"], text=True).splitlines()
    assert any(row.startswith("n") and Path(row[1:]).resolve() == executable for row in images)
    queue = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
    jobs = json.loads(queue.read_text())["jobs"]
    assert any(job["state"] in ["planned", "running"] for job in jobs.values()), "Finite work already ended; do not restart it for an observation"
    return pid


def probe_active_work(root, evidence, plan_file="replacement-plan.json"):
    pane = inventory_input.owned_pane(root.resolve())
    samples = []
    for columns, rows in [(120,36), (160,48), (96,89), (80,24), (60,20), (40,12)]:
        subprocess.run(["tmux", "resize-window", "-t", pane, "-x", str(columns), "-y", str(rows)], check=True)
        for index in range(4):
            pid = live_dispatcher(root, evidence, plan_file)
            subprocess.run(["tmux", "send-keys", "-t", pane, "C-u"], check=True)
            text = f"draft-{columns}-{rows}-{index}"
            started = time.monotonic_ns()
            subprocess.run(["tmux", "send-keys", "-t", pane, "-l", "--", text], check=True)
            screen, elapsed = observe_echo(pane, text, started)
            assert live_dispatcher(root, evidence, plan_file) == pid
            assert elapsed <= 300, f"Observed echo {elapsed:.2f} ms exceeds the 300 ms fixture bound"
            (evidence / (text + "-echo.txt")).write_text(screen)
            samples.append({"columns":columns,"rows":rows,"elapsedMs":elapsed,"dispatcherPid":pid})
    subprocess.run(["tmux", "resize-window", "-t", pane, "-x", "120", "-y", "36"], check=True)
    subprocess.run(["tmux", "send-keys", "-t", pane, "C-u"], check=True)
    save(evidence, "active-typing-timing", {"samples":samples,"medianMs":statistics.median(s["elapsedMs"] for s in samples),
        "maxMs":max(s["elapsedMs"] for s in samples),"budgetMs":300,"clock":"monotonic",
        "endpoint":"after capture returns","liveDispatcherBeforeAndAfterEverySample":True,
        "providerCalls":0,"sourceExecuted":False,"notAPercentileOrReferenceParityClaim":True})


def observe_echo(pane, text, started):
    while time.monotonic_ns() - started < 2_000_000_000:
        screen = subprocess.check_output(["tmux", "capture-pane", "-p", "-t", pane], text=True)
        elapsed = (time.monotonic_ns() - started) / 1_000_000
        if text in screen:
            return screen, elapsed
        time.sleep(.005)
    raise AssertionError("The owned active-work composer did not echo its draft")


def completed(root, evidence):
    invariant(root, evidence)
    plan = json.loads((evidence / "replacement-plan.json").read_text())
    deadline = time.monotonic() + 60
    queue = root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json"
    while time.monotonic() < deadline:
        jobs = json.loads(queue.read_text())["jobs"]
        if all(job["state"] == "completed" for job in jobs.values()):
            counts = current_counts(root, evidence)
            assert len(jobs) == 9 and counts["investigation_work_attempts"] == 9
            assert counts["finding_observations"] == 9 and counts["review_decisions"] == 0
            save(evidence, "completed-work-check", {"jobs":9,"counts":counts,"providerCalls":0,"sourceExecuted":False})
            return
        time.sleep(.1)
    raise AssertionError("Observe the same dispatcher; do not relaunch on a completion observation timeout")


if __name__ == "__main__":
    root, evidence, home, stage = Path(sys.argv[1]), Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve(), sys.argv[4]
    if stage == "crash": crash(root, evidence, home)
    elif stage == "probe": probe_active_work(root, evidence)
    elif stage == "completed": completed(root, evidence)
    else: inspect(root, evidence, stage)
