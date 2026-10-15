"""Real metadata approval over an owned monorepo. No model or source execution."""
import json
import sys
from pathlib import Path

import shared_monorepo
from installed_scope_study import current_counts, native, save


def allowance(root, evidence, plan):
    output = native(root, evidence, "accounting-status", ["run", "campaign:allowance", "--input",
        json.dumps({"investigationId":plan["investigationId"]})])
    return output["data"]["allowance"]


def inspect(root, evidence, stage):
    assert shared_monorepo.hashes(root) == json.loads((evidence / "source-before.json").read_text())
    assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text()).get("active") is None
    plan, _ = shared_monorepo.selected_plan(root, evidence)
    if stage == "initialize":
        output = native(root, evidence, "initial-accounting", ["run", "campaign:approve-allowance", "--input",
            json.dumps({"investigationId":plan["investigationId"], "expectedRevision":0,
                "model":"openai-codex:gpt-5.5", "maxProviderCalls":3, "protectedReviewCalls":1,
                "reason":"Owned offline metadata test; no provider request or job is authorized"})])
        value = output["data"]["allowance"]
    else:
        value = allowance(root, evidence, plan)
    counts = current_counts(root, evidence)
    assert all(count in [None, 0] for count in counts.values()), counts
    assert value["committedCalls"] == value["unresolvedCalls"] == 0
    assert not (root / ".kuzushi/v3/campaigns" / plan["campaignId"] / "queue.json").exists()
    if stage == "approved":
        assert value["revision"] == 2 and value["limits"] == {"maxProviderCalls":1, "protectedReviewCalls":1}
        assert value["workPlan"]["campaignId"] == plan["campaignId"]
        assert len(value["workPlan"]["jobs"]) == 9
    else:
        assert value["revision"] == 1 and value["limits"] == {"maxProviderCalls":3, "protectedReviewCalls":1}
        assert value.get("workPlan") is None
    save(evidence, stage + "-hierarchy-check", {"revision":value["revision"], "limits":value["limits"],
        "jobsStarted":0, "providerCalls":0, "sourceExecuted":False, "counts":counts})


if __name__ == "__main__":
    inspect(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3])
