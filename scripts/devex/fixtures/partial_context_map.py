"""Partial source context through local scans and review. No inference or source execution."""
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
import bounded_semgrep
from installed_scope_study import native
from inventory_input import owned_pane
from secret_settings import ledger


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source_hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["service/notice.py", "loose.py", "oversized.txt"]}


def partial_tool(root, evidence, home, label, tool):
    env = dict(os.environ, HOME=str(home))
    command = [env["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root), "run", tool, "--input", "{}"]
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=40)
    (evidence / (label + ".stdout.json")).write_text(result.stdout)
    (evidence / (label + ".stderr.log")).write_text(result.stderr)
    output = json.loads(result.stdout)
    assert result.returncode == 4 and output["ok"] and output["status"] == "partial", result.stderr
    return output["data"]


def seed(root, evidence, home):
    bounded_semgrep.seed(root, evidence, home)
    (root / "oversized.txt").write_bytes(b'a' * 262145)
    (evidence / "runtime-home.txt").write_text(str(home))
    snapshot = partial_tool(root, evidence, home, "partial-snapshot", "context:build")
    assert snapshot["partialCoverage"]
    catalog = partial_tool(root, evidence, home, "partial-catalog", "entry-points:extract")
    assert catalog["snapshotCoverage"]["state"] == "partial"
    path = root / ".kuzushi/manual-context.json"
    document = json.loads(path.read_text())
    document["systemContext"] += "\nOversized fixture material exceeds the 256 KiB content-inspection limit. Unseen entry points remain unknown; complete repository coverage is not claimed."
    document["deprioritized"] = [{"entryPointId": row["id"], "reason": "Owned static policy fixture. This extracted surface is retained for source review without an execution or vulnerability claim."} for row in catalog["entryPoints"]]
    path.write_text(json.dumps(document, indent=2) + "\n")
    (evidence / "import-command.txt").write_text("run threat-model:import " + json.dumps({"path":str(path), "activate":False,"label":"Partial owned policy context"}))
    save(evidence, "source-before", source_hashes(root))
    save(evidence, "catalog-count", catalog["total"])


def imported_context(root, evidence):
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    imports = bounded_semgrep.run_results(root, "threat-model:import")
    assert len(imports) == 1
    folder, result = imports[0]
    assert result["status"] == "partial"
    verification = result["data"]["verification"]
    assert verification["verdict"] == "partial" and verification["groundingSource"] == "partial-catalog"
    assert verification["coverageConsidered"] == json.loads((evidence / "catalog-count.json").read_text())
    assert verification["coverageGaps"] == 0 and "262144" in verification["groundingDegraded"]
    assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text()).get("active") is None
    return result["data"]["modelRef"]


def verify(root, evidence, stage):
    reference = imported_context(root, evidence)
    events = [json.loads(line) for line in (root / ".kuzushi/v3/workflow/phase-attempts.jsonl").read_text().splitlines() if line]
    maps = [row for row in events if row["event"] == "phase_attempt_completed" and row["phase"] == "map"]
    assert len(maps) == 1 and maps[0]["outcome"] == "partial"
    decisions = [row for row in events if row["event"] == "phase_attempt_disposition_recorded" and row["attemptId"] == maps[0]["attemptId"]]
    assert len(decisions) == (0 if stage == "pending" else 1)
    if decisions:
        assert decisions[0]["disposition"]["acknowledged_partial"] is True
    if stage in ["draft", "scanned", "exported", "restarted"]:
        plan = bounded_semgrep.plan(root, evidence)
        assert plan["baseInput"]["threatModelRef"] == reference
        if stage != "draft":
            bounded_semgrep.completed(root, evidence, plan)
        if stage in ["exported", "restarted"]:
            bounded_semgrep.exported(root, plan)
            report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
            text = json.dumps(report)
            assert "partial-catalog" in text and "per-file inspection cap" in text, "Report must retain accepted context limitations"
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for name in ["investigation_call_reservations", "investigation_allowance_revisions"]:
            count = db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
            assert count == (1 if name == "investigation_allowance_revisions" and stage in ["scanned", "exported", "restarted"] else 0)
    save(evidence, stage + "-check", {"modelRef":reference,"sourceUnchanged":True,"activeContextUnchanged":True,"partialMapAcknowledged":bool(decisions),"providerRequests":0,"sourceExecution":False})


def seek_limit(root, evidence, name="compact-limit-page"):
    pane = owned_pane(root.resolve())
    subprocess.run(["tmux", "send-keys", "-t", pane, "Home"], check=True)
    for page in range(60):
        text = subprocess.check_output(["tmux", "capture-pane", "-p", "-t", pane], text=True)
        if "262144" in text:
            assert page <= 6, "The compact reader must reach the inspection limit without a long receipt hunt"
            save(evidence, name, {"pageDownPresses":page,"sourceExecuted":False})
            return
        subprocess.run(["tmux", "send-keys", "-t", pane, "NPage"], check=True)
        time.sleep(0.12)
    raise AssertionError("Partial inspection limit must be reachable in the canonical result reader")


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif sys.argv[3] == "limit-page":
        seek_limit(root, evidence)
    elif sys.argv[3] == "report-limit-page":
        seek_limit(root, evidence, "report-limit-page")
    else:
        deadline = time.monotonic() + 45
        while True:
            try:
                verify(root, evidence, sys.argv[3])
                break
            except (AssertionError, FileNotFoundError, json.JSONDecodeError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)
