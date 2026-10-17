"""Exact per-boundary context choices through native dispatch. No inference or source execution."""
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from finite_scopes import prepare, source_hashes
from context_comparison import import_context
from investigation_journey import plans


def seed(root, evidence, home):
    prepare(root, evidence, home)
    binary = os.environ["KUZUSHI_NATIVE_BIN"]
    first = import_context(binary, root, evidence, "Alpha")
    active = import_context(binary, root, evidence, "Beta")
    (evidence / "scope-context-before.json").write_text(json.dumps({
        "first": first, "active": active, "sources": source_hashes(root)}))


def verify(root, evidence, stage):
    before = json.loads((evidence / "scope-context-before.json").read_text())
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == before["active"]
    assert source_hashes(root) == before["sources"]
    assert len(manifest["models"]) == 3
    copy = manifest["models"][-1]
    revision = copy["revisions"][-1]
    exact = {"modelId": copy["modelId"], "revisionId": revision["revisionId"], "sha256": revision["sha256"]}
    path = root / ".kuzushi/threat-models/objects" / ("sha256-" + exact["sha256"].removeprefix("sha256:") + ".json")
    assert json.loads(path.read_text())["systemContext"] == "Owned boundary context"
    entries = sorted([plan for plan in plans(root) if plan["kind"] == "scope-study"], key=lambda plan: plan["createdAtMs"])
    assert len(entries) == (1 if stage in ["planned", "approved"] else 2)
    first = entries[0]
    assert first["scopeStudy"]["inheritedThreatModelRef"] == before["active"]
    assert first["scopeStudy"]["selections"] == [
        {"scopeId": "app", "passes": 3, "threatModelRef": exact},
        {"scopeId": "other", "passes": 3, "threatModelRef": None}]
    for plan in entries:
        assert plan["jobCount"] == 6 and plan["workers"] == 1
        assert plan["scopeStudy"]["unplannedScopeIds"] == ["integration"]
        assert not (root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json").exists()
        cases = {case["id"]: case for case in plan["scopeStudy"]["cases"]}
        expected_app = exact if plan == first else before["active"]
        assert cases["app"]["baseInput"]["threatModelRef"] == expected_app
        assert cases["other"]["baseInput"]["threatModelRef"] is None
        for job in plan["jobs"]:
            assert job["input"]["threatModelRef"] == cases[job["caseId"]]["baseInput"]["threatModelRef"]
    assert len({plan["investigationId"] for plan in entries}) == 1
    if len(entries) == 2:
        assert entries[-1]["scopeStudy"]["selections"][0] == {"scopeId": "app", "passes": 3}
    database = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts"]:
            if table in tables:
                assert db.execute("select count(*) from " + table).fetchone()[0] == 0
        approvals = []
        if "investigation_allowance_revisions" in tables:
            approvals = [json.loads(row[0]) for row in db.execute("select approval_json from investigation_allowance_revisions order by revision")]
        assert len(approvals) == (0 if stage == "planned" else 1)
        if approvals:
            assert approvals[0]["workPlan"]["planSha256"] == "sha256:" + hashlib.sha256(json.dumps(first, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            assert approvals[0]["limits"] == {"maxProviderCalls": 8, "protectedReviewCalls": 2}
    assert not (evidence / "finite-scope-calls.jsonl").exists()
    if stage == "restarted":
        verify_narrow_provenance(evidence, before, entries[-1])
    (evidence / "scope-resume.txt").write_text("campaign " + entries[-1]["campaignId"])
    (evidence / ("scope-context-" + stage + ".json")).write_text(json.dumps({
        "plans": len(entries), "fixedJobs": 6, "activeUnchanged": True,
        "exactOverride": exact, "omittedSibling": True, "providerRequests": 0,
        "sourceExecuted": False, "newApprovalRequired": len(entries) == 2}, indent=2))


def verify_narrow_provenance(evidence, before, plan):
    paths = sorted(evidence.glob("*-recovered*40x12.txt"))
    assert len(paths) >= 19
    body = "".join(narrow_detail_text(path.read_text()) for path in paths)
    compact = "".join(body.split())
    source = plan["scopeStudy"]["cases"][0]["equivalence"]["components"]["targetGit"]
    for item in ["Context actually frozen for scans:", before["active"]["revisionId"],
                 before["active"]["sha256"], "Source SHA:", source["sha"],
                 "changed from commit", "Source identity:", "Scope reference:"]:
        assert "".join(item.split()) in compact, "Narrow paging hid " + item


def narrow_detail_text(text):
    lines = text.splitlines()
    control = next(i for i, line in enumerate(lines)
                   if "↑↓ Enter choose" in line and "PgUp/Dn" in line)
    assert control >= 3, "Narrow context reader has no detail viewport"
    return "".join(line.strip().strip("│").strip()
                   for line in lines[control - 3:control])


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, sys.argv[3])
