"""Literal scope paths through an installed scanner, never executing target source."""
import hashlib
import json
import sys
import time
from pathlib import Path

import bounded_semgrep
from installed_scope_study import current_counts, native, save

MEMBERS = {"Spaced app": [" app /lib.py"], "Other source": ["app/lib.py", "loose.py"]}


def hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for files in MEMBERS.values() for name in files}


def seed(root, evidence, home):
    bounded_semgrep.seed(root, evidence, home)
    (root / "service/notice.py").unlink()
    (root / "service").rmdir()
    for names in MEMBERS.values():
        for name in names:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('# Owned inert policy text. Never executed.\nprint("OWNER_POLICY_REVIEW")\n')
    path = root / ".kuzushi/manual-context.json"
    doc = json.loads(path.read_text())
    doc["title"] = "Owned literal directory context"
    doc["systemContext"] = "Three inert Python files contain the same harmless owner-policy marker. The directories app and ' app ' are distinct literal names. loose.py is a separate root file. No target execution or vulnerability claim is established."
    doc["dfd"]["nodes"] = [{"id": "source-" + str(i), "name": name,
        "type": "data-store", "trustZone": "repository", "description": name + " is owned inert policy text.",
        "purpose": "Supplies a literal source observation for owner review."}
        for i, name in enumerate(hashes(root))]
    doc["openQuestions"] = []
    path.write_text(json.dumps(doc, indent=2) + "\n")
    for name, text in {"spaced-path": " app ", "other-paths": "app\nloose.py", "invalid-path": " . "}.items():
        (evidence / (name + ".txt")).write_text(text)
    (evidence / "runtime-home.txt").write_text(str(home))
    save(evidence, "source-before", hashes(root))


def review(root, evidence):
    return native(root, evidence, "scope-latest", ["run", "pack:scopes", "--input", '{"operation":"latest"}'])["data"]["review"]


def verify_boundaries(root, evidence, stage):
    value = review(root, evidence)
    draft, coverage = value["record"]["draft"], value["coverage"]
    assert coverage["enumeratedFiles"] == 3 and coverage["enumerationComplete"]
    assert coverage["uncoveredFiles"]["total"] == coverage["overlaps"]["total"] == 0
    if stage == "whole":
        assert len(draft["scopes"]) == 1 and draft["scopes"][0]["paths"] == ["."]
        assert not draft["exclusions"]
    else:
        assert {s["name"]: s["paths"] for s in draft["scopes"]} == {"Spaced app": [" app "], "Other source": ["app", "loose.py"]}
        expected = {name: list(paths) for name, paths in MEMBERS.items()}
        if stage == "excluded":
            assert draft["exclusions"][0]["path"] == " app "
            assert coverage["excludedFiles"]["files"] == MEMBERS["Spaced app"]
            expected["Spaced app"] = []
        else:
            assert not draft["exclusions"] and coverage["excludedFiles"]["total"] == 0
        for scope in draft["scopes"]:
            assert coverage["discoveryMembers"].get(scope["id"], {}).get("files", []) == expected[scope["name"]]
    if stage == "invalid":
        assert value["reference"] == json.loads((evidence / "scope-restored.json").read_text())["reference"]
    assert bool(value["record"]["acceptance"]) == (stage == "accepted")
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    assert all(count in [None, 0] for count in current_counts(root, evidence).values())
    save(evidence, "scope-" + stage, value)


def plan(root, evidence):
    plans = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    assert len(plans) == 1 and plans[0]["kind"] == "scope-study"
    value = plans[0]
    assert value["jobCount"] == len(value["jobs"]) == 6 and value["workers"] == 1
    cases = {case["id"]: case for case in value["scopeStudy"]["cases"]}
    assert {case["label"] for case in cases.values()} == set(MEMBERS)
    accepted = json.loads((evidence / "scope-accepted.json").read_text())
    assert value["scopeStudy"]["unplannedScopeIds"] == []
    for case in cases.values():
        scan = case["baseInput"]
        assert case["passes"] == 3 and case["equivalence"]["components"].get("model") is None
        assert scan["scanScopeRef"]["proposal"] == accepted["reference"]
        assert scan["tasks"] == ["semgrep"] and scan["semgrepTimeoutMs"] == 60000
        assert all(not scan[key] for key in ["triage", "verify", "patch", "autoPatch", "pocExecution", "dynamicAnalysis"])
    (evidence / "resume-command.txt").write_text("campaign " + value["campaignId"])
    return value, cases


def verify_work(root, evidence, stage):
    value, cases = plan(root, evidence)
    queue_path = root / ".kuzushi/v3/campaigns" / value["campaignId"] / "queue.json"
    if stage == "draft":
        assert not queue_path.exists()
        assert all(count in [None, 0] for count in current_counts(root, evidence).values())
        save(evidence, "draft-check", {"jobs": 6, "workers": 1, "providerCalls": 0, "sourceExecuted": False})
        return
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if queue_path.exists() and all(j["state"] == "completed" for j in json.loads(queue_path.read_text())["jobs"].values()):
            break
        time.sleep(0.2)
    queue = json.loads(queue_path.read_text())["jobs"]
    assert len(queue) == 6 and all(j["state"] == "completed" and j["attempts"] == j["dispatches"] == 1 for j in queue.values())
    for job in value["jobs"]:
        result = json.loads((root / ".kuzushi/v3/runs" / queue[job["jobId"]]["runId"] / "result.json").read_text())
        assert result["status"] == "completed"
        assert sorted(f["file_path"] for f in result["data"]["coreFindings"]) == MEMBERS[cases[job["caseId"]]["label"]]
    counts = current_counts(root, evidence)
    assert counts["finding_observations"] == 9 and counts["investigation_work_attempts"] == 6
    assert counts["investigation_call_reservations"] == 0
    occurrence = native(root, evidence, "occurrence", ["findings", "batch", value["campaignId"], "--json"])
    for case in occurrence["cases"]:
        work = case["occurrence"]
        assert work["planned"] == work["completed"] == 3
        assert len(work["rows"]) == len(MEMBERS[cases[case["id"]]["label"]])
        assert all(row["seen"] == 3 for row in work["rows"])
        for row in work["rows"]:
            suffix = "spaced" if cases[case["id"]]["label"] == "Spaced app" else "root" if "loose.py" in row["representativeLocation"] else "plain"
            (evidence / ("open-" + suffix + ".txt")).write_text("open " + row["representativeFingerprint"])
    if stage in ["exported", "external", "restart"]:
        assert counts["review_decisions"] == 3
        report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
        assert report["count"] == 3 and all(f["reviewDecision"] == "deferred" for f in report["findings"])
        assert sorted(f["location"]["file"] for f in report["findings"]) == sorted(hashes(root))
        receipt = report["metadata"]["investigation"]
        assert receipt["campaignId"] == value["campaignId"] and receipt["observationCount"] == 9
        assert receipt["reviewedCount"] == 3 and receipt["confirmedCount"] == 0
        calls = receipt["allowance"]["currentInvestigation"]
        assert calls["committedCalls"] == calls["unresolvedCalls"] == 0
        assert calls["limits"] == {"maxProviderCalls": 1, "protectedReviewCalls": 1}
    if stage in ["external", "restart"]:
        external = json.loads((root / ".kuzushi/reports/VULN-FINDINGS.json").read_text())
        assert external["scan_completed"] is True and len(external["findings"]) == 3
    save(evidence, stage + "-check", {"campaignId": value["campaignId"], "jobs": 6, "counts": counts, "providerCalls": 0, "sourceExecuted": False})


def verify(root, evidence, stage):
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text()).get("active") is None
    if stage in ["split", "excluded", "restored", "invalid", "whole", "accepted"]:
        verify_boundaries(root, evidence, stage)
    else:
        verify_work(root, evidence, stage)


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]))
    else:
        verify(root, evidence, stage)
