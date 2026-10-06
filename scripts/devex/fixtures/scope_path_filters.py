"""Explicit study-local repair of saved path filters. No scan starts."""
import json
import sys
import time
from pathlib import Path
import study_engines


def wait_for_saved_filter(options):
    for _ in range(100):
        if options.is_file():
            value = json.loads(options.read_text())
            if value.get("bindings", {}).get("global/tool/sast:scan", {}).get("paths") == ["excluded.py"]:
                return
        time.sleep(0.1)
    raise AssertionError("The shell did not persist the requested global path filter")


def verify(root, evidence, stage):
    options = evidence / "home/.kuzushi/v3/options.json"
    saved = evidence / "global-options-before.json"
    if stage == "filters":
        wait_for_saved_filter(options)
        saved.write_bytes(options.read_bytes())
    else:
        assert options.read_bytes() == saved.read_bytes(), "Study repair must preserve global options"
        study_engines.verify(root, evidence, "picker" if stage == "canceled" else stage)
        if stage in ("draft", "restarted"):
            plans = list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
            plan = json.loads(plans[0].read_text())
            assert plan["baseInput"]["paths"] == [], "Empty local filters must override stored filters"
            assert all(job["input"]["paths"] == [] for job in plan["jobs"])
    (evidence / f"path-filters-{stage}.json").write_text(json.dumps({
        "stage": stage, "globalOptionsPreserved": True,
        "scanJobsStarted": 0, "providerCalls": 0,
    }, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        study_engines.exact_scope.seed(root, evidence)
    else:
        verify(root, evidence, stage)
