"""Explicit diagram planning and installed source inspection on owned inert text."""
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import bounded_semgrep
from context_comparison import run_tool
from context_diagram import document
from installed_scope_study import native

SELECTED = [" app /lib.py", "app/lib.py"]
SOURCES = SELECTED + ["app/lib.py.extra.py", "loose.py"]


def save(evidence, name, value):
    bounded_semgrep.save(evidence, name, value)


def hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES}


def graph(label, paths):
    value = document(label)
    value["systemContext"] = "Owned inert source contains a harmless policy marker. Read-only source inspection establishes no runtime flow or vulnerability verdict."
    value["attackSurface"]["entryPoints"] = [
        {"id": "owned-" + str(index), "name": "Owned policy source " + str(index),
         "path": path, "targetElementIds": ["api", "request", "edge"],
         "description": "Source evidence for a bounded owner review; no execution."}
        for index, path in enumerate(paths)]
    return value


def seed(root, evidence, home):
    bounded_semgrep.seed(root, evidence, home)
    (root / "service/notice.py").unlink()
    (root / "service").rmdir()
    for name in SOURCES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('# Owned inert text. Never executed.\nprint("OWNER_POLICY_REVIEW")\n')
    output = run_tool(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, "inactive-alpha",
                      "threat-model:import", {"document": graph("Alpha", SELECTED), "label": "Alpha", "activate": False})
    save(evidence, "context-refs", {"selected": output["data"]["modelRef"]})
    save(root / ".kuzushi", "manual-context", graph("Beta", [SOURCES[2]]))
    save(evidence, "source-before", hashes(root))
    (evidence / "runtime-home.txt").write_text(str(home))


def counts(root, evidence):
    return bounded_semgrep.counts(root, evidence)


def invariant(root, evidence):
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    refs = json.loads((evidence / "context-refs.json").read_text())
    if "active" in refs:
        assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())["active"] == refs["active"]
    assert counts(root, evidence)["investigation_call_reservations"] in [None, 0]
    return refs


def plan(root, evidence):
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    assert len(plans) == 1 and plans[0]["kind"] == "scan-batch"
    value = plans[0]
    refs = invariant(root, evidence)
    assert value["trialsPlanned"] == len(value["jobs"]) == 3 and value["workers"] == 1
    scan = value["baseInput"]
    assert scan["paths"] == SELECTED and scan["threatModelRef"] == refs["selected"]
    assert "scanScopeRef" not in scan and scan["scanContextRef"]["object"]["sizeBytes"] > 0
    assert scan["tasks"] == ["semgrep"] and scan["semgrepTimeoutMs"] == 60000
    assert scan["semgrepConfig"] == [str(evidence / "local-rules.yaml")]
    assert all(not scan[key] for key in ["triage", "verify", "patch", "autoPatch", "pocExecution", "dynamicAnalysis"])
    assert value["equivalence"].get("model") is None
    (evidence / "resume-command.txt").write_text("campaign " + value["campaignId"])
    return value


def completed(root, evidence, value):
    queue = json.loads((root / ".kuzushi/v3/campaigns" / value["campaignId"] / "queue.json").read_text())["jobs"]
    assert len(queue) == 3 and all(row["state"] == "completed" and row["attempts"] == row["dispatches"] == 1 for row in queue.values())
    current = counts(root, evidence)
    assert current["finding_observations"] == 6 and current["investigation_work_attempts"] == 3
    assert current["investigation_call_reservations"] == 0
    for row in queue.values():
        result = json.loads((root / ".kuzushi/v3/runs" / row["runId"] / "result.json").read_text())
        assert result["status"] == "completed"
        assert sorted(item["file_path"] for item in result["data"]["coreFindings"]) == SELECTED
    output = native(root, evidence, "exact-recurrence", ["findings", "batch", value["campaignId"], "--json"])
    assert output["planned"] == output["completed"] == 3 and len(output["rows"]) == 2
    for row in output["rows"]:
        assert row["seen"] == 3 and row["representativeSeverity"] == "info"
        suffix = "spaced" if " app /" in row["representativeLocation"] else "plain"
        (evidence / ("open-" + suffix + ".txt")).write_text("open " + row["representativeFingerprint"])
    return current, output


def verify(root, evidence, stage):
    if stage == "mapped":
        refs = invariant(root, evidence)
        refs["active"] = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())["active"]
        assert refs["active"] and refs["active"] != refs["selected"]
        save(evidence, "context-refs", refs)
    invariant(root, evidence)
    if stage in ["mapped", "navigation"]:
        assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
        assert all(value in [None, 0] for value in counts(root, evidence).values())
        save(evidence, stage + "-check", {"jobs": 0, "providerRequests": 0, "sourceExecuted": False})
        return
    value = plan(root, evidence)
    if stage == "draft":
        assert not (root / ".kuzushi/v3/campaigns" / value["campaignId"] / "queue.json").exists()
        assert all(value in [None, 0] for value in counts(root, evidence).values())
        save(evidence, "draft-check", {"jobs": 3, "workers": 1, "providerRequests": 0, "sourceExecuted": False})
        return
    deadline = time.monotonic() + 60
    while True:
        try:
            current, occurrence = completed(root, evidence, value)
            break
        except (AssertionError, FileNotFoundError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)
    if stage in ["exported", "restarted"]:
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert report["count"] == 2 and current["review_decisions"] == 2
        assert sorted(row["location"]["file"] for row in report["findings"]) == SELECTED
        assert all(row["reviewDecision"] == "deferred" for row in report["findings"])
        receipt = report["metadata"]["investigation"]
        assert receipt["campaignId"] == value["campaignId"] and receipt["observationCount"] == 6
        assert receipt["confirmedCount"] == 0 and receipt["reviewedCount"] == 2
        assert receipt["allowance"]["currentInvestigation"]["committedCalls"] == 0
    save(evidence, stage + "-check", {"jobs": 3, "counts": current, "providerRequests": 0, "sourceExecuted": False})


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]))
    else:
        verify(root, evidence, stage)
