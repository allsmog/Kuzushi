"""Owned Scan planning with absent credentials and no provider execution."""
import json
import subprocess
import sys
from pathlib import Path

from catalog_dependencies import SOURCE, SHA, git, source_files
from secret_settings import ledger, save


def seed(parent, evidence, home):
    root = parent / "repository"
    assert not root.exists() and home == (evidence / "home").resolve()
    assert git(SOURCE, "branch", "--show-current") == "main" and git(SOURCE, "rev-parse", "HEAD") == SHA
    subprocess.run(["git", "clone", "--local", "--no-hardlinks", "--branch", "main",
                    str(SOURCE), str(root)], capture_output=True, check=True)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    save(evidence, "source-before", {"sha": SHA, "files": source_files(root)})


def verify(parent, evidence, stage):
    root = parent / "repository"
    before = json.loads((evidence / "source-before.json").read_text())
    assert git(root, "branch", "--show-current") == "main" and git(root, "rev-parse", "HEAD") == SHA
    assert source_files(root) == before["files"]
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
                  for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts", "investigation_allowance_revisions"]}
    assert all(value == 0 for value in counts.values()), counts
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    if stage in ("prepared", "map", "both"):
        assert len(plans) == (2 if stage == "both" else 1)
        kinds = {plan["kind"]: plan for plan in plans}
        assert set(kinds) == ({"context-study", "scan-batch"} if stage == "both" else
                              {"context-study" if stage == "map" else "scan-batch"})
        if "scan-batch" in kinds:
            verify_scan(kinds["scan-batch"], evidence)
        if "context-study" in kinds:
            verify_map(kinds["context-study"], evidence)
    else:
        assert not plans
    save(evidence, "planning-invariants", {"sha": SHA, "counts": counts,
         "providerRequests": 0, "sourceExecuted": False, "sourceUnchanged": True})


def verify_scan(plan, evidence):
    assert len(plan["jobs"]) == 3 and plan["workers"] == 1
    assert plan["baseInput"]["tasks"] == ["agentic"]
    assert plan["baseInput"]["threatModelRef"] is None
    assert all(plan["baseInput"][key] is False for key in ["triage", "verify", "autoPatch"])
    save(evidence, "frozen-discovery-plan", plan)


def verify_map(plan, evidence):
    assert plan["requiresWorkApproval"] and plan["workers"] == 1
    assert [job["tool"] for job in plan["jobs"]] == [
        "context:build", "entry-points:extract", "threat-model:build"]
    context = plan["jobs"][-1]["input"]
    assert context["activate"] is False and context["newModel"] is True
    assert context["pipeline"] == "single" and context["variantScan"] is False
    assert context["sources"] == ["source-code"]
    assert context["model"] == "openai-codex:gpt-5.5"
    save(evidence, "frozen-map-plan", plan)


if __name__ == "__main__":
    parent, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == "seed":
        seed(parent, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(parent, evidence, sys.argv[3])
