"""Inspect the retained scope's shared allowance without admitting work."""
import json
import sys
from pathlib import Path

from retained_scope_reader import verify


def check(evidence, stage, home=None):
    if stage == "seed":
        verify(evidence, stage, home)
        return
    verify(evidence, "accounting")
    checked = []
    for path in sorted(evidence.glob("*budget*.txt")):
        text = " ".join(path.read_text().replace("│", " ").split())
        assert "$0" not in text, path
        if path.stem.endswith("-budget-tail"):
            assert "Shared investigation: monorepo-scope-quality-20261025 r3" in text, path
            assert "Dollar ceiling: not enforced" in text, path
            assert "0 other calls left" in text, path
        else:
            for fact in ["calls 3/3", "0 calls left", "0 unsettled", "0 Review protected", "cost not recorded"]:
                assert fact in text, (path, fact)
        checked.append(path.name)
    assert len(checked) >= 9, checked
    (evidence / "scope-budget-check.json").write_text(json.dumps({
        "checkedFrames": checked, "sharedCallsCommitted": 3,
        "remainingCalls": 0, "unresolvedCalls": 0, "dollarCharges": "unknown",
        "newProviderRequests": 0, "scopeAccepted": False, "sourceExecuted": False,
    }, indent=2) + "\n")


if __name__ == "__main__":
    check(Path(sys.argv[1]).resolve(), sys.argv[2],
          Path(sys.argv[3]).resolve() if len(sys.argv) == 4 else None)
