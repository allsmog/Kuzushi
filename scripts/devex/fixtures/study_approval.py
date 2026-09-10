"""Build review input from the real offline study draft; no model execution."""
import hashlib
import json
import sys
from pathlib import Path


def approval_command(root, output):
    plan = json.loads((root / ".kuzushi/v3/campaigns/offline-finite/plan.json").read_text())
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    approval = {
        "investigationId": "offline-finite",
        "expectedRevision": 0,
        "model": "openai-codex:gpt-5.5",
        "maxProviderCalls": 9,
        "protectedReviewCalls": 3,
        "reason": "Offline TUI approval; no provider execution",
        "campaignId": "offline-finite",
        "campaignPlanSha256": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "campaignJobs": 3,
        "maxJobAttempts": 1,
    }
    output.write_text("run campaign:approve-allowance " + json.dumps(approval, separators=(",", ":")))


if __name__ == "__main__":
    approval_command(Path(sys.argv[1]), Path(sys.argv[2]))
