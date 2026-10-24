"""Large declared topology and finite installed scans over owned, unexecuted source."""
import hashlib
import json
import re
import sys
import time
from pathlib import Path

import bounded_semgrep
from installed_scope_study import native

COMPONENTS = 96
TAIL = "modules/worker_095.py"
SOURCES = [f"modules/worker_{i:03}.py" for i in range(1, COMPONENTS)] + ["README.md"]


def save(folder, name, value):
    bounded_semgrep.save(folder, name, value)


def hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES}


def topology():
    nodes = [{"id":"caller", "name":"Declared caller", "type":"external-entity", "trustZone":"public"}]
    flows, entries = [], []
    for i in range(1, COMPONENTS):
        key, path = f"worker-{i:03}", f"modules/worker_{i:03}.py"
        nodes.append({"id":key, "name":"Tail worker 095" if i == 95 else f"Worker {i:03}",
             "type":"process", "trustZone":"isolated" if i == 95 else "application",
             "description":f"Declared transfer stage in {path}. The fixture source is never executed.",
             "purpose":"Makes the owned source chain inspectable without asserting deployed isolation."})
        boundary = ["entry-boundary"] if i == 1 else ["tail-boundary"] if i == 95 else []
        flow = f"transfer-{i:03}"
        flows.append({"id":flow, "sourceId":"caller" if i == 1 else f"worker-{i-1:03}",
             "targetId":key, "description":f"Declared transfer {i:03}", "trustBoundaryIds":boundary})
        entries.append({"id":f"source-{i:03}", "name":f"Owned stage {i:03}", "path":path,
             "description":"Harmless local policy marker in owned source; no vulnerability verdict.",
             "targetElementIds":[key, flow, *boundary]})
    boundaries = [{"id":"entry-boundary", "name":"Declared entry boundary", "outerZone":"public",
        "innerZone":"application", "crossingFlowIds":["transfer-001"]},
        {"id":"tail-boundary", "name":"Declared tail boundary", "outerZone":"application",
        "innerZone":"isolated", "crossingFlowIds":["transfer-095"]}]
    return {"version":"1", "methodology":"stride", "title":"Owned large source chain",
        "systemContext":"Ninety-five owned modules declare a source transfer chain. A manual fixture diagram records that chain; trust-zone isolation is an unverified design assumption. No target source is imported or executed and no vulnerability is asserted.",
        "dfd":{"nodes":nodes,"flows":flows,"trustBoundaries":boundaries},
        "attackSurface":{"entryPoints":entries,"roleGates":[],"externalSinks":[],"trustedCallers":[]},
        "threats":[],"assets":[],"openQuestions":[],"summary":{"evidenceType":"Owned declared topology; no runtime proof."}}


def seed(root, evidence, home):
    assert root == evidence / "fixture-target"
    bounded_semgrep.seed(root, evidence, home)
    (root / "service/notice.py").unlink()
    (root / "service").rmdir()
    (root / "loose.py").unlink()
    (root / "modules").mkdir()
    for i in range(1, COMPONENTS):
        next_stage = f"    from .worker_{i+1:03} import transfer_{i+1:03}\n    return transfer_{i+1:03}(value)\n" if i < 95 else "    return value\n"
        (root / f"modules/worker_{i:03}.py").write_text(
            f'# Owned static fixture. Never imported or executed.\ndef transfer_{i:03}(value):\n    print("OWNER_POLICY_REVIEW")\n' + next_stage)
    (root / "README.md").write_text("# Owned source-only chain\nThe declared isolation boundaries are design assumptions, not runtime evidence.\n")
    save(root / ".kuzushi", "manual-context", topology())
    save(evidence, "source-before", hashes(root))
    (evidence / "runtime-home.txt").write_text(str(home))


def invariant(root, evidence):
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    current = bounded_semgrep.counts(root, evidence)
    assert current["investigation_call_reservations"] in [None, 0]
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    before = evidence / "mapped-context.json"
    if before.exists():
        assert manifest["active"] == json.loads(before.read_text())["active"]
    return manifest["active"], current


def plan(root, evidence):
    values = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    assert len(values) == 1
    value = values[0]
    active, current = invariant(root, evidence)
    assert value["kind"] == "scan-batch" and value["trialsPlanned"] == len(value["jobs"]) == 3
    assert value["workers"] == 1
    scan = value["baseInput"]
    assert scan["paths"] == [TAIL] and scan["threatModelRef"] == active
    assert scan["tasks"] == ["semgrep"] and scan["scanContextRef"]["object"]["sizeBytes"] > 0
    assert all(not scan[key] for key in ["triage","verify","patch","autoPatch","pocExecution","dynamicAnalysis"])
    assert value["equivalence"].get("model") is None
    (evidence / "resume-command.txt").write_text("campaign " + value["campaignId"])
    return value, current


def completed(root, evidence, value):
    queue = json.loads((root / ".kuzushi/v3/campaigns" / value["campaignId"] / "queue.json").read_text())["jobs"]
    assert len(queue) == 3 and all(row["state"] == "completed" and row["attempts"] == row["dispatches"] == 1 for row in queue.values())
    for row in queue.values():
        result = json.loads((root / ".kuzushi/v3/runs" / row["runId"] / "result.json").read_text())
        assert result["status"] == "completed"
        assert [finding["file_path"] for finding in result["data"]["coreFindings"]] == [TAIL]
    active, current = invariant(root, evidence)
    assert current["finding_observations"] == current["investigation_work_attempts"] == 3
    occurrence = native(root, evidence, "tail-recurrence", ["findings","batch",value["campaignId"],"--json"])
    assert occurrence["planned"] == occurrence["completed"] == 3 and len(occurrence["rows"]) == 1
    gate = occurrence["gate"]
    assert gate["status"] == gate["securityStatus"] == "disabled"
    assert gate["operationalStatus"] == "complete" and not gate["policy"].get("failOn")
    assert gate["blockingSafeFoldCount"] == 0 and not gate["sarifWritten"]
    row = occurrence["rows"][0]
    assert row["seen"] == 3 and row["representativeSeverity"] == "info"
    (evidence / "open-tail.txt").write_text("open " + row["representativeFingerprint"])
    return current


def verify(root, evidence, stage):
    active, current = invariant(root, evidence)
    if stage in ["mapped","canceled-draft"]:
        assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
        assert all(value in [None, 0] for value in current.values())
        save(evidence, "mapped-context", {"active":active})
    else:
        value, current = plan(root, evidence)
        if stage == "draft":
            assert not (root / ".kuzushi/v3/campaigns" / value["campaignId"] / "queue.json").exists()
            assert all(count in [None, 0] for count in current.values())
        else:
            current = completed(root, evidence, value)
        if stage in ["exported","restarted"]:
            report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
            assert report["count"] == current["review_decisions"] == 1
            assert report["findings"][0]["location"]["file"] == TAIL
            assert report["findings"][0]["reviewDecision"] == "deferred"
            receipt = report["metadata"]["investigation"]
            assert receipt["campaignId"] == value["campaignId"] and receipt["observationCount"] == 3
            assert receipt["confirmedCount"] == 0 and receipt["reviewedCount"] == 1
            assert receipt["allowance"]["currentInvestigation"]["committedCalls"] == 0
    if stage == "restarted":
        for sgr in re.findall(r"\x1b\[([\d;]*)m",next(evidence.glob("*-recovered-report.ansi")).read_text()):
            assert not any(30 <= int(code) <= 38 or 40 <= int(code) <= 48 or 90 <= int(code) <= 107 for code in sgr.split(';') if code)
    if stage in ["completed-screen", "restarted"]:
        captures = [path.read_text() for path in evidence.glob("[0-9][0-9]-*.txt")]
        assert not any("Ledger refresh failed:" in capture for capture in captures)
        save(evidence, stage + "-feedback", {
            "captureCount": len(captures), "ledgerRefreshErrors": 0,
            "pendingReceiptFeedbackObserved": any("Work receipts pending" in capture for capture in captures)})
    save(evidence, stage + "-check", {"components":96,"flows":95,"counts":current,
         "sourceUnchanged":True,"providerRequests":0,"targetSourceExecuted":False})


def wait(root, evidence, stage):
    deadline = time.monotonic() + 65
    while True:
        try:
            verify(root, evidence, stage)
            return
        except (AssertionError, FileNotFoundError, json.JSONDecodeError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        wait(root, evidence, sys.argv[3])
