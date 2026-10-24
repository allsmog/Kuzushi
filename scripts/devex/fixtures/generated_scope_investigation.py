"""Generated boundary context through six fixed scans, triage and restart. Transport is intercepted."""
import hashlib
import json
import shutil
import subprocess
import sys
from contextlib import closing
from pathlib import Path
from group_context import prepare as prepare_group, sources
from investigation_journey import plans, wait_jobs, read_native
from secret_settings import ledger
from scope_findings import wait_frame


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def prepare(root, evidence, home):
    prepare_group(root, evidence, home)
    # The temporary HOME is nested in an ignored repository artifact directory.
    # Give it an owned Git boundary so global settings use its own ignore policy.
    subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(home)], check=True)
    # This journey requires actual Map acceptance, not the older fixture's skipped checkpoint.
    (root / ".kuzushi/v3/workflow/phase-attempts.jsonl").unlink()
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/generated_scope_provider.mjs", evidence / "provider.mjs")
    document = {"version": "1", "methodology": "stride", "title": "Owned accepted root context",
        "systemContext": "ROOT_ACCEPTED_CONTEXT. Four owned files contain static comments. App and adapter form one boundary. Shared source supplies context. No deployed application or vulnerability is established.",
        "dfd": {"nodes": [{"id": name, "name": name.title() + " source", "type": "data-store",
            "trustZone": "repository", "description": path + " contains owned static source.",
            "purpose": "Supplies bounded source evidence.", "sourceRefs": [path + ":1"]}
            for name, path in [("app", "app/reader.rs"), ("adapter", "adapter/entry.rs"),
                               ("other", "other/reader.rs"), ("shared", "shared/context.rs")]],
            "flows": [], "trustBoundaries": []}, "threats": [], "summary": {},
        "openQuestions": ["Static comments do not establish runtime data flows."]}
    (root / ".kuzushi/manual-generated-root.json").write_text(json.dumps(document, indent=2) + "\n")


def stored_contexts(root):
    directory = root / ".kuzushi/threat-models"
    manifest = json.loads((directory / "manifest.json").read_text())
    entries = {}
    for model in manifest["models"]:
        revision = model["revisions"][-1]
        reference = {"modelId": model["modelId"], "revisionId": revision["revisionId"], "sha256": revision["sha256"]}
        path = directory / "objects" / ("sha256-" + reference["sha256"].removeprefix("sha256:") + ".json")
        payload = path.read_bytes()
        assert "sha256:" + hashlib.sha256(payload).hexdigest() == reference["sha256"]
        document = json.loads(payload)
        entries[document["title"]] = (reference, document)
    return manifest, entries


def fixed_context(root, evidence, stage):
    source_capture = next(evidence.glob("*-source-context.txt")).read_text()
    assert "could not persist options" not in source_capture
    assert (evidence / "home/.kuzushi/v3/options.json").is_file()
    before = json.loads((evidence / "group-before.json").read_text())
    manifest, contexts = stored_contexts(root)
    assert manifest["active"] == before["active"] and sources(root) == before["sources"]
    root_ref = contexts["Owned accepted root context"][0]
    assert root_ref != before["active"]
    entries = plans(root)
    context = [plan for plan in entries if plan["kind"] == "context-study"]
    assert len(context) == 1
    context = context[0]
    assert context["workers"] == 1 and len(context["jobs"]) == 1
    origin = context["scopeStudyOrigin"]
    assert origin["scopeCases"] == [{"scopeId": "app", "passes": 3}, {"scopeId": "other", "passes": 3, "threatModelRef": None}]
    assert origin["scanInput"]["threatModelRef"] == root_ref
    assert context["jobs"][0]["input"]["inheritedContextRef"] == root_ref
    if stage == "context-draft":
        assert len(contexts) == 2 and not (evidence / "generated-scope-calls.jsonl").exists()
        return context, None
    work = wait_jobs(root, context, {"completed"})
    assert all(job["attempts"] == 1 for job in work.values())
    manifest, contexts = stored_contexts(root)
    reference, document = contexts["Owned generated boundary context"]
    receipt = document["provenance"]["scopeContext"]["receipt"]
    assert receipt["inheritedContextRef"] == root_ref
    assert receipt["synthesisRequests"] == 1 and not receipt["completeRepositoryCoverage"]
    assert receipt["discoveryFileCount"] == 2 and receipt["sharedFileCount"] == 1
    assert {file["path"] for file in receipt["sourceEvidence"]["files"]} == set(before["sources"]) - {"other/reader.rs"}
    assert not receipt["sourcePartial"] and receipt["sourceEvidence"]["omissions"] == {}
    (evidence / "generated-context-resume.txt").write_text("campaign " + context["campaignId"])
    save(evidence, "generated-reference", reference)
    return context, reference


def scan_plan(root, evidence, context, reference):
    entries = [plan for plan in plans(root) if plan["kind"] == "scope-study"]
    assert len(entries) == 1
    plan = entries[0]
    assert plan["investigationId"] == context["investigationId"]
    assert plan["workers"] == 1 and plan["jobCount"] == len(plan["jobs"]) == 6
    assert plan["scopeStudy"]["unplannedScopeIds"] == ["integration"]
    cases = {case["id"]: case for case in plan["scopeStudy"]["cases"]}
    assert set(cases) == {"app", "other"}
    assert cases["app"]["baseInput"]["threatModelRef"] == reference
    assert cases["other"]["baseInput"]["threatModelRef"] is None
    assert plan["scopeStudy"]["inheritedThreatModelRef"] == context["scopeStudyOrigin"]["scanInput"]["threatModelRef"]
    for job in plan["jobs"]:
        assert job["input"]["triage"] is False and job["input"]["verify"] is False and job["input"]["autoPatch"] is False
    return plan


def completed_scans(root, evidence, plan):
    jobs = wait_jobs(root, plan, {"completed"})
    assert len(jobs) == 6 and all(job["attempts"] == 1 for job in jobs.values())
    report = read_native(root, evidence, "generated-occurrence", ["findings", "batch", plan["campaignId"], "--json"])
    for boundary in report["cases"]:
        occurrence = boundary["occurrence"]
        assert (occurrence["planned"], occurrence["completed"], occurrence["failed"], occurrence["pending"]) == (3, 3, 0, 0)
        assert len(occurrence["rows"]) == 1 and occurrence["rows"][0]["seen"] == 3
        (evidence / ("open-" + boundary["id"] + ".txt")).write_text("open " + occurrence["rows"][0]["representativeFingerprint"])


def verify_export(root, evidence, plan, reference, stage):
    payload = (root / ".kuzushi/reports/findings.json").read_bytes()
    if stage == "restarted":
        assert payload == (evidence / "export-before-restart.json").read_bytes()
    report = json.loads(payload)
    assert report["count"] == 2
    assert all(row["reviewDecision"] == "rejected_false_positive" for row in report["findings"])
    assert {row["location"]["file"] for row in report["findings"]} == {"app/reader.rs", "other/reader.rs"}
    receipt = report["metadata"]["investigation"]
    assert receipt["campaignId"] == plan["campaignId"] and receipt["observationCount"] == 6
    assert receipt["reviewedCount"] == 2 and receipt["unplannedScopeIds"] == ["integration"]
    state = receipt["scope"]["app"]["contextEvidence"]
    assert state["contextRef"] == reference
    projection = state["sourceContext"]
    assert projection["projection"] == "metadata-only" and projection["sourceTextIncluded"] is False
    source = projection["scopeContext"]["receipt"]
    assert source["discoveryFileCount"] == 2 and source["sharedFileCount"] == 1
    assert source["sourcePartial"] is False and source["completeRepositoryCoverage"] is False
    assert len(source["sourceEvidence"]["files"]) == 3
    assert all("text" not in line for file in source["sourceEvidence"]["files"] for line in file["lines"])
    assert receipt["scope"]["other"]["contextEvidence"]["status"] == "omitted"
    account = receipt["allowance"]["currentInvestigation"]
    assert account["committedCalls"] == 7 and account["unresolvedCalls"] == 0
    assert account["limits"] == {"maxProviderCalls": 9, "protectedReviewCalls": 2}
    if stage == "exported":
        (evidence / "export-before-restart.json").write_bytes(payload)


def verify(root, evidence, stage):
    if stage == "report-frame":
        return wait_frame(root, evidence, "report", "format ", footer_rows=8)
    context, reference = fixed_context(root, evidence, stage)
    if stage == "context-draft":
        return
    expected = 7 if stage in {"completed", "exported", "restarted"} else 1
    if stage != "context-finished":
        plan = scan_plan(root, evidence, context, reference)
        if stage == "scan-draft":
            assert not (root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json").exists()
        else:
            completed_scans(root, evidence, plan)
    calls = [json.loads(line) for line in (evidence / "generated-scope-calls.jsonl").read_text().splitlines()]
    assert len(calls) == expected and len({row["bridgePid"] for row in calls}) == expected
    assert all(row["liveRequests"] == 0 and row["sourceExecuted"] is False for row in calls)
    assert calls[0]["kind"] == "context"
    if expected == 7:
        assert sorted(row["scope"] for row in calls[1:]) == ["app"] * 3 + ["other"] * 3
        assert all(row["contextBinding"] == ("selected" if row["scope"] == "app" else "omitted") for row in calls[1:])
    with closing(ledger(root, evidence)) as db:
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == expected
        assert db.execute("select count(*) from investigation_call_reservations where review=1 or settled_at is null").fetchone()[0] == 0
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == (6 if expected == 7 else 0)
        approvals = [json.loads(row[0]) for row in db.execute("select approval_json from investigation_allowance_revisions order by revision")]
        assert len(approvals) == (2 if expected == 7 else 1)
        assert approvals[-1]["limits"] == {"maxProviderCalls": 9, "protectedReviewCalls": 2}
    if stage in {"exported", "restarted"}:
        verify_export(root, evidence, plan, reference, stage)
    save(evidence, stage + "-verified", {"interceptedRequests": expected, "liveRequests": 0,
        "sourceExecuted": False, "activeContextUnchanged": True, "sourceUnchanged": True,
        "contextRef": reference, "fixedDiscoveryJobs": 6 if stage != "context-finished" else 0})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, sys.argv[3])
