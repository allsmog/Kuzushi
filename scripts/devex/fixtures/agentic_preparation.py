"""Real prepared engine with intercepted transport; no live inference or source execution."""
import json
import shutil
import sqlite3
import sys
from pathlib import Path
from investigation_journey import seed, source_hashes, plans, wait_jobs, read_native
from rejected_context import execute


def prepare(root, evidence, home):
    seed(root, evidence, home)
    repo = Path(__file__).resolve().parents[3]
    shutil.copyfile(repo / "scripts/devex/fixtures/preparation_provider.mjs", evidence / "provider.mjs")
    draft = execute(root, home, evidence, "preparation-plan", "campaign:study", {
        "campaignId": "preparation-study", "investigationId": "preparation-investigation", "trials": 2,
        "scanInput": {"taskMode": "manual", "tasks": ["agentic"], "threatModelRef": None,
            "scanContextRef": None, "maxInventoryFiles": 1, "maxBytesPerFile": 64, "maxIterations": 1, "mcps": False}})
    execute(root, home, evidence, "preparation-approval", "campaign:approve-allowance", {
        "investigationId": "preparation-investigation", "expectedRevision": 0,
        "model": "openai-codex:gpt-5.5", "maxProviderCalls": 4, "protectedReviewCalls": 2,
        "reason": "Two intercepted source-only fixture calls; no live inference.",
        "campaignId": "preparation-study", "campaignPlanSha256": draft["planSha256"],
        "campaignJobs": 2, "maxJobAttempts": 1})
    path = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"event": "phase_checkpoint_skipped", "phase": "map",
        "targetSnapshot": {"target": str(root), "dirty": False}, "recordedAtUnix": 1}) + "\n")


def verify(root, evidence):
    assert source_hashes(root) == json.loads((evidence / "before.json").read_text())["sources"]
    plan = next(p for p in plans(root) if p["campaignId"] == "preparation-study")
    jobs = wait_jobs(root, plan, {"completed"})
    assert len(jobs) == 2
    calls = [json.loads(line) for line in (evidence / "preparation-calls.jsonl").read_text().splitlines()]
    assert len(calls) == 2 and len({row["bridgePid"] for row in calls}) == 2
    for job in jobs.values():
        path = root / ".kuzushi/v3/runs" / job["runId"] / "result.json"
        value = json.loads(path.read_text())
        encoded = json.dumps(value)
        assert '"selectedFiles": 1' in encoded and '"maxSnippetBytes": 64' in encoded
        assert '"maxFileReadBytes": 4097' in encoded
        assert "snippet file limit reached" in encoded
    with sqlite3.connect(root / ".kuzushi/v3/index.sqlite3") as db:
        assert db.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 2
        assert db.execute("select count(*) from finding_observations").fetchone()[0] == 0
        assert db.execute("select count(*) from investigation_call_reservations where review=1").fetchone()[0] == 0
        approval = json.loads(db.execute("select approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()[0])
        assert approval["limits"] == {"maxProviderCalls": 4, "protectedReviewCalls": 2}
    (evidence / "preparation-verified.json").write_text(json.dumps({"fixedJobs": 2,
        "committedCalls": 2, "protectedReviewCalls": 2, "liveRequests": 0, "sourceExecuted": False}, indent=2))


def main():
    root, evidence = [Path(value) for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        prepare(root, evidence, Path(sys.argv[4]))
    else:
        verify(root, evidence)
        if sys.argv[3] == "report":
            paths = sorted(evidence.glob("*-report-*40x12.txt"))
            bodies = []
            for path in paths:
                rows = path.read_text().splitlines()[1:]
                footer = next(index for index, row in enumerate(rows) if row.startswith("⛭"))
                bodies.extend(rows[:footer])
            text = " ".join(" ".join(bodies).split())
            for phrase in ["2 committed / 4 calls", "2 protected review", "Preparation:", "snippet file limit reached", "remaining preparation is uninspected", "no complete coverage claim"]:
                assert phrase in text, "Narrow report never exposed " + phrase


if __name__ == "__main__":
    main()
