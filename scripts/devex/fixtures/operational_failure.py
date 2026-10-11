"""Read-only checks for actual owned operational failure receipts."""
import json
import sys
from pathlib import Path


def failed_receipts(root):
    receipts = {}
    for path in (root / ".kuzushi/v3/runs").glob("*/result.json"):
        value = json.loads(path.read_text())
        if value.get("status") != "failed":
            continue
        context = value.get("fallback_context", {})
        if context.get("failedStage") == "coverage:sweep":
            receipts[path.parent.name] = value
    return receipts


root, evidence = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
action = sys.argv[3]
receipts = failed_receipts(root)
if action == "before":
    (evidence / "failure-before.json").write_text(json.dumps(sorted(receipts)) + "\n")
else:
    before = json.loads((evidence / "failure-before.json").read_text())
    new = {key: value for key, value in receipts.items() if key not in before}
    assert new, "The native TUI must persist a new failed result."
    for value in new.values():
        context = value["fallback_context"]
        assert "dirty tree" in context["cause"]
        assert context["claimsForbidden"]
        assert context["fallbackPrompt"]
        assert context["recoveryOptions"]
        assert value["errors"]
    (evidence / (action + "-failure-check.json")).write_text(json.dumps({
        "newFailureRunIds": sorted(new), "fullFailureContextRetained": True,
        "humanVerdictsCreated": False, "syntheticFailurePayload": False,
    }, indent=2) + "\n")
