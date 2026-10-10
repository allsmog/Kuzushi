"""Recorded Source views over an owned, unapproved runtime-free plan."""
import json
import shutil
import sys
from pathlib import Path
import preparation_inputs as preparation


def inspect(root, evidence):
    preparation.no_work(root, evidence, "source-sections")
    frames = sorted(evidence.glob("*source-options-page-40x12*.txt"))
    text = "".join("".join(path.read_text().split()) for path in frames)
    recorded = json.loads((evidence / "frozen-plan.stdout.json").read_text())["data"]["scanInput"]
    for key in recorded:
        assert json.dumps(key) in text, "Exact options omitted key: " + key
    returned = next(evidence.glob("*returned-inputs.txt")).read_text()
    assert "RECORDED ENGINE INPUTS" in returned and "Tab Settings" in returned
    assert len(frames) >= 12 and len({path.read_text() for path in frames}) > 3
    facts = json.loads((evidence / "frozen-evidence.json").read_text())
    (evidence / "source-sections-check.json").write_text(json.dumps({
        "planSha256": facts["planSha256"], "fixedJobs": facts["jobs"],
        "optionsKeysInspected": len(recorded), "providerRequests": 0,
        "scanJobsStarted": 0, "sourceUnchanged": True,
    }, indent=2) + "\n")


root, evidence, stage = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
if stage == "seed":
    preparation.seed(root, evidence, Path(sys.argv[4]))
    preparation.frozen(root, evidence)
    node = shutil.which("node")
    assert node, "The installed kz wrapper requires Node.js"
    (evidence / "bin/node").symlink_to(node)
elif stage == "inspect":
    inspect(root, evidence)
elif stage == "recover":
    preparation.no_work(root, evidence, "source-recovered")
else:
    raise SystemExit("Unknown source-section stage: " + stage)
