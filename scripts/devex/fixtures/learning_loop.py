"""Installed source inspection, reviewed learning and a finite context experiment."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from rejected_context import execute
from secret_settings import ledger, save

BASELINE = "owned-learning-baseline"
INVESTIGATION = "owned-learning-accounting"
MARKER = "Owned greeting policy reminder. No defect is claimed."


def run(root, evidence, name, tool, value):
    return execute(root, Path((evidence / "runtime-home.txt").read_text()), evidence, name, tool, value)


def source_hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["hello.py", ".gitignore"]}


def queue(root, campaign):
    return json.loads((root / ".kuzushi/v3/campaigns" / campaign / "queue.json").read_text())["jobs"]


def wait_completed(root, campaign):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            jobs = queue(root, campaign)
            if len(jobs) == 3 and all(job["state"] == "completed" for job in jobs.values()):
                return jobs
            assert all(job["state"] != "failed" for job in jobs.values()), jobs
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        time.sleep(0.2)
    raise AssertionError("The three approved local jobs did not complete")


def inspect_scan(root, run_id):
    value = json.loads((root / ".kuzushi/v3/runs" / run_id / "result.json").read_text())
    assert value["status"] == "completed" and value["data"]["observationsCount"] == 1
    findings = value["data"]["coreFindings"]
    assert len(findings) == 1 and findings[0]["file_path"] == "hello.py", findings
    receipt = next(row for row in value["data"]["nativeInspections"] if row["engine"] == "semgrep")
    assert receipt["excludedPaths"] == ["**/.kuzushi/**"]
    return value


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "hello.py").write_text('# Owned greeting. Never executed.\nprint("owned source")\n')
    (root / ".gitignore").write_text("# Workspace state uses its own managed exclusions.\n")
    (evidence / "runtime-home.txt").write_text(str(home))
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    provider = evidence / "provider.mjs"
    shutil.copyfile(Path(__file__).with_name("learning_provider.mjs"), provider)
    shutil.copyfile(Path(__file__).with_name("untrusted_context.mjs"), evidence / "untrusted_context.mjs")
    credentials = home / ".kuzushi/learning-credentials.json"
    credentials.write_text(json.dumps({"openai-codex": {"access": "offline-learning-fixture", "expires": 99999999999999}}))
    credentials.chmod(0o600)
    bridge = ["node", "--import", str(provider), str(Path(__file__).resolve().parents[2] / "langgraph-bridge.mjs")]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\nlanggraph_bridge_command = ' + json.dumps(bridge)
        + '\n[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\nallow_env_token = false\n')
    rules = evidence / "owned-rules.yaml"
    rules.write_text("rules:\n  - id: owned-greeting-policy\n    languages: [generic]\n    severity: INFO\n    message: " + MARKER + "\n    pattern: Owned greeting.\n")
    save(evidence, "source-before", source_hashes(root))
    run(root, evidence, "source-context", "context:build", {"enrichment": False})
    document = {"version": "1", "methodology": "stride", "title": "Owned policy baseline",
        "systemContext": "hello.py is inert owned greeting source. A local rule reports a literal policy marker. No vulnerability, runtime behavior or fix is established.",
        "dfd": {"nodes": [{"id": "text", "name": "Greeting policy source", "type": "data-store",
            "trustZone": "repository", "description": "hello.py contains an owned greeting literal.",
            "purpose": "Supplies static evidence for the learning workflow."}], "flows": [], "trustBoundaries": []},
        "threats": [], "openQuestions": [], "summary": {"evidenceType": "Owned inert policy text"}}
    imported = run(root, evidence, "base-context", "threat-model:import",
        {"document": document, "label": "Owned policy baseline", "activate": True})
    scan = {"taskMode": "manual", "tasks": ["semgrep", "agentic"], "semgrepConfig": [str(rules)],
        "semgrepTimeoutMs": 60000, "threatModelRef": imported["modelRef"]}
    plan = run(root, evidence, "baseline-plan", "campaign:study", {"campaignId": BASELINE,
        "investigationId": INVESTIGATION, "trials": 3, "workers": 1, "scanInput": scan})
    run(root, evidence, "baseline-approval", "campaign:approve-allowance", {"investigationId": INVESTIGATION,
        "expectedRevision": 0, "model": "openai-codex:gpt-5.5", "maxProviderCalls": 6, "protectedReviewCalls": 0,
        "reason": "Six intercepted adapter requests across two three-job studies. No live provider request or target execution.",
        "campaignId": BASELINE, "campaignPlanSha256": plan["planSha256"], "campaignJobs": 3, "maxJobAttempts": 1})
    command = [os.environ["KUZUSHI_NATIVE_BIN"], "--target", str(root), "campaign", "batch", BASELINE]
    result = subprocess.run(command, env=dict(os.environ, HOME=str(home)), capture_output=True, text=True, timeout=120)
    (evidence / "baseline-dispatch.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stderr
    jobs = wait_completed(root, BASELINE)
    for job in jobs.values():
        inspect_scan(root, job["runId"])
    latest = jobs[max(jobs)]["runId"]
    with ledger(root, evidence) as db:
        observation = json.loads(db.execute("select finding_json from finding_observations order by created_seq desc limit 1").fetchone()[0])
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 3
        assert db.execute("select count(*) from review_decisions").fetchone()[0] == 0
    (evidence / "open.txt").write_text("open generation:" + str(observation["id"]))
    (evidence / "candidate-open.txt").write_text("scan batch --prior-run " + latest)
    (evidence / "rule-setting.txt").write_text("set semgrepConfig " + json.dumps([str(rules)]))
    for name, text in {"title": "Owned greeting review lesson", "text": "Inspect the recorded policy marker.\nUnicode café remains historical guidance.",
        "applies": "Manual source review of owned greeting policy text.", "limits": "This is a policy marker, not a vulnerability. Later source needs independent review.",
        "reason": "Reviewed the exact text and historical limits.", "retire": "Retire this guidance after the bounded context experiment."}.items():
        (evidence / (name + ".txt")).write_text(text)
    mirror = root / ".kuzushi/threat-model.json"
    save(evidence, "before", {"baseRef": imported["modelRef"], "baselineRun": latest,
        "activeMirrorSha256": hashlib.sha256(mirror.read_bytes()).hexdigest(), "scanner": shutil.which("semgrep")})
    verify(root, evidence, "baseline")


def lesson_page(root, evidence, stage):
    return run(root, evidence, "lessons-" + stage, "findings:lessons", {})["rows"]


def verify_context(root, evidence, stage, before):
    catalog = run(root, evidence, "contexts-" + stage, "threat-model:models", {})
    manifest = catalog.get("manifest", catalog)
    assert manifest["active"] == before["baseRef"]
    if stage not in ["copy", "candidate-draft", "candidate-complete", "exported", "retired", "restarted"]:
        return None
    assert len(manifest["models"]) == 2
    copied = manifest["models"][-1]
    revision = copied["revisions"][-1]
    reference = {"modelId": copied["modelId"], "revisionId": revision["revisionId"], "sha256": revision["sha256"]}
    read = run(root, evidence, "copy-read-" + stage, "threat-model:read", {"threatModelRef": reference})
    assert read["document"]["lessonSelection"]["sourceModelRef"] == before["baseRef"]
    assert len(read["document"]["reviewedLessons"]) == 1
    assert read["lessonState"]["usable"] == (stage not in ["retired", "restarted"])
    save(evidence, "copied-context", reference)
    return reference


def verify_candidate(root, evidence, stage, before, copied):
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    assert len(plans) == 2
    candidate = next(plan for plan in plans if plan["campaignId"] != BASELINE)
    assert candidate["contextExperiment"]["baselineRunId"] == before["baselineRun"]
    assert candidate["investigationId"] == INVESTIGATION and candidate["workers"] == 1
    assert len(candidate["jobs"]) == 3 and candidate["baseInput"]["threatModelRef"] == copied
    frozen = run(root, evidence, "frozen-context-" + stage, "threat-model:read", {
        "threatModelRef": copied, "threatModelDigestRef": candidate["baseInput"]["threatModelDigestRef"]})
    preview = frozen["scannerContextPreview"]
    assert preview["origin"] == "frozen-study" and "Owned greeting review lesson" in preview["text"]
    assert "Unicode café" in preview["text"]
    saved = evidence / "supplied-context.json"
    if saved.exists():
        assert json.loads(saved.read_text())["text"] == preview["text"]
    else:
        save(evidence, "supplied-context", preview)
    (evidence / "resume-command.txt").write_text("campaign " + candidate["campaignId"])
    if stage == "candidate-draft":
        assert not (root / ".kuzushi/v3/campaigns" / candidate["campaignId"] / "queue.json").exists()
    else:
        jobs = wait_completed(root, candidate["campaignId"])
        for job in jobs.values():
            inspect_scan(root, job["runId"])
    save(evidence, "candidate-plan", candidate)


def verify_export(root, evidence, stage):
    report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
    assert report["count"] == 1 and report["findings"][0]["reviewDecision"] == "confirmed"
    finding = report["findings"][0]
    # The earlier decision remains historical. Unversioned re-observation does
    # not establish present applicability or attach another generation's lesson.
    assert finding["reviewDecisionBasis"]["sourceApplicability"] == "later_source_unverified"
    assert finding.get("lessons", []) == []
    receipt = report["metadata"]["investigation"]
    assert receipt["reassessmentRequiredCount"] == 1
    candidate = json.loads((evidence / "candidate-plan.json").read_text())
    assert receipt["campaignId"] == candidate["campaignId"] and receipt["observationCount"] == 3
    assert receipt["allowance"]["currentInvestigation"]["limits"] == {"maxProviderCalls": 6, "protectedReviewCalls": 0}
    if stage == "restarted":
        # The old export remains an authentic accepted-lesson snapshot.
        assert report == json.loads((evidence / "export-before-retirement.json").read_text())
    else:
        save(evidence, "export-before-retirement", report)


def verify(root, evidence, stage):
    before = json.loads((evidence / "before.json").read_text())
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    assert hashlib.sha256((root / ".kuzushi/threat-model.json").read_bytes()).hexdigest() == before["activeMirrorSha256"]
    rows = lesson_page(root, evidence, stage)
    state = {"baseline": None, "confirmed": None, "draft": "draft", "accepted": "accepted", "copy": "accepted",
        "candidate-draft": "accepted", "candidate-complete": "accepted", "exported": "accepted", "retired": "retired", "restarted": "retired"}[stage]
    assert len(rows) == (0 if state is None else 1)
    if state:
        assert rows[0]["lesson"]["state"] == state
        assert rows[0]["lesson"]["origin"]["decision"]["decision"]["author"] == "human"
    copied = verify_context(root, evidence, stage, before)
    advanced = stage in ["candidate-complete", "exported", "retired", "restarted"]
    if stage in ["candidate-draft", "candidate-complete", "exported", "retired", "restarted"]:
        verify_candidate(root, evidence, stage, before, copied)
    if stage in ["exported", "restarted"]:
        verify_export(root, evidence, stage)
    with ledger(root, evidence) as db:
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] for name in
            ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]}
        assert counts["finding_observations"] == counts["investigation_work_attempts"] == (6 if advanced else 3)
        assert counts["review_decisions"] == (0 if stage == "baseline" else 1)
        assert counts["investigation_call_reservations"] == (6 if advanced else 3)
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()[0])
        assert approval["limits"] == {"maxProviderCalls": 6, "protectedReviewCalls": 0}
    calls = [json.loads(line) for line in (evidence / "learning-calls.jsonl").read_text().splitlines()]
    assert len(calls) == (6 if advanced else 3)
    assert all(call["reviewedLessonSupplied"] == (index >= 3) for index, call in enumerate(calls))
    if advanced:
        preview = json.loads((evidence / "supplied-context.json").read_text())
        assert all(call["contextSha256"] == preview["sha256"] for call in calls[3:])
    save(evidence, stage + "-check", {"stage": stage, "counts": counts, "lessonState": state,
        "sourceAndActiveContextUnchanged": True, "interceptedRequests": len(calls), "providerRequests": 0, "targetSourceExecuted": False})


if __name__ == "__main__":
    stage, target, output = sys.argv[1:4]
    root, evidence = Path(target).resolve(), Path(output).resolve()
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, stage)
