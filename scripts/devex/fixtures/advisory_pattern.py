"""Supplied inert diff, unaccepted draft and separately requested source search."""
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path
from variant_draft import seed as draft_seed
from rejected_context import execute
from advisory_observations import decision_digest

DRAFT = "ndiff:extract-fix-pattern"
SEARCH = "ndiff:hunt-variants"


def seed(root, evidence, home):
    root.mkdir(parents=True, exist_ok=True)
    text = "--- a/hello.txt\n+++ b/hello.txt\n@@ -1 +1 @@\n-Owned greeting\n+Owned changed greeting\n"
    text += "#" * (255 - len(text)) + "界omitted owned context; no defect is claimed\n"
    (root / "owned-context.diff").write_text(text)
    draft_seed(root, evidence, home)
    shutil.copyfile(Path(__file__).with_name("advisory_pattern_provider.mjs"), evidence / "provider.mjs")
    execute(root, home, evidence, "bounded-pair-approval", "campaign:approve-allowance", {
        "investigationId": "owned-pattern", "expectedRevision": 1, "model": "openai-codex:gpt-5.5",
        "maxProviderCalls": 3, "protectedReviewCalls": 1,
        "reason": "Fully intercepted owned draft and separately requested search"})
    (evidence / "decision-before.sha256").write_text(decision_digest(root))
    (evidence / "diff-before.sha256").write_text(hashlib.sha256(text.encode()).hexdigest())
    (evidence / "command.txt").write_text("run " + DRAFT + " " + json.dumps({
        "patchPath": "owned-context.diff", "offline": True, "maxSourceBytes": 256,
        "allowanceRef": reference("owned-draft")}))


def reference(work):
    return {"schemaVersion": 1, "investigationId": "owned-pattern", "revision": 2, "workId": work}


def result(root, tool):
    deadline = time.monotonic() + 20
    records = []
    while time.monotonic() < deadline:
        records = [(p.parent, json.loads(p.read_text())) for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
        records = [(p, r) for p, r in records if r.get("tool") == tool]
        if len(records) == 1 and records[0][1]["status"] != "running":
            break
        time.sleep(.05)
    assert len(records) == 1 and records[0][1]["status"] == "partial", records
    path, run = records[0]
    assert not run.get("phase")
    return path, run, json.loads((path / "result.json").read_text())["data"]


def verify(root, evidence, stage):
    assert decision_digest(root) == (evidence / "decision-before.sha256").read_text()
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest() == (evidence / "source-before.sha256").read_text()
    assert hashlib.sha256((root / "owned-context.diff").read_bytes()).hexdigest() == (evidence / "diff-before.sha256").read_text()
    active = json.loads((evidence / "active-before.json").read_text())
    assert hashlib.sha256(Path(active["path"]).read_bytes()).hexdigest() == active["sha256"]
    calls = evidence / "advisory-pattern-calls.jsonl"
    if stage == "before":
        assert not calls.exists()
        return
    path, run, data = result(root, DRAFT)
    assert data["draft"] is True and data["accepted"] is False and data["contextActivated"] is False
    source = data["sourceReceipt"]
    assert source["kind"] == "supplied-file" and source["complete"] is False and source["includedBytes"] == 255
    assert source["digest"] == "sha256:" + (evidence / "diff-before.sha256").read_text()
    assert source["bytes"] == len((root / "owned-context.diff").read_bytes()) and source["omittedBytes"] == source["bytes"] - 255
    digest = hashlib.sha256((path / "result.json").read_bytes()).hexdigest()
    if stage == "draft":
        (evidence / "draft-result.sha256").write_text(digest)
        (evidence / "replay.txt").write_text("replay " + run["runId"])
        (evidence / "search.txt").write_text("run " + SEARCH + " " + json.dumps({
            "pattern": data["pattern"], "advisoryId": "OWNED-GREETING", "includeVendored": False,
            "maxFindings": 1, "maxModelTurns": 1, "allowanceRef": reference("explicit-search")}))
    else:
        assert digest == (evidence / "draft-result.sha256").read_text()
        _, _, search = result(root, SEARCH)
        assert search["findings"] == [] and search["patternAccepted"] is False
    expected = 1 if stage == "draft" else 2
    assert len(calls.read_text().splitlines()) == expected
    account = execute(root, Path(os.environ["HOME"]), evidence, "allowance-" + stage,
        "campaign:allowance", {"investigationId": "owned-pattern"})["allowance"]
    assert account["revision"] == 2 and account["committedCalls"] == expected and account["reviewCalls"] == 0
    assert account["limits"]["protectedReviewCalls"] == 1
    lessons = execute(root, Path(os.environ["HOME"]), evidence, "lessons-" + stage, "findings:lessons", {})
    assert lessons["rows"] == []
    (evidence / (stage + "-check.json")).write_text(json.dumps({"interceptedRequests": expected,
        "liveRequests": 0, "sourceExecution": False, "sourceUnchanged": True, "activeContextUnchanged": True,
        "exactHumanDecisionPreserved": True, "draftAccepted": False, "acceptedLessons": 0,
        "committedCalls": expected, "protectedReviewCalls": 1, "phaseContinuation": False}, indent=2) + "\n")


if __name__ == "__main__":
    stage, root, evidence, *home = sys.argv[1:]
    root, evidence = Path(root).resolve(), Path(evidence).resolve()
    if stage == "seed":
        seed(root, evidence, Path(home[0]).resolve())
    else:
        verify(root, evidence, stage)
