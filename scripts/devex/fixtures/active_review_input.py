"""Observe Review typing during the owned finite native study. No inference."""
import json
import subprocess
import sys
from pathlib import Path

import inventory_input
import prepared_study_recovery
import shared_monorepo
from installed_scope_study import save


def probe(root, evidence):
    plan, _ = shared_monorepo.selected_plan(root, evidence)
    save(evidence, "active-review-plan", plan)
    prepared_study_recovery.probe_active_work(root, evidence, "active-review-plan.json")
    timing = json.loads((evidence / "active-typing-timing.json").read_text())
    timing["surface"] = "Review"
    save(evidence, "active-review-timing", timing)
    pane = inventory_input.owned_pane(root.resolve())
    subprocess.run(["tmux", "send-keys", "-t", pane, "-l", "--", "retained-review-draft"], check=True)


if __name__ == "__main__":
    probe(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
