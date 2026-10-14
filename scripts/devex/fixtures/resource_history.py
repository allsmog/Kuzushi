"""Cold bounded history and retry UI. Owned artifacts, no live inference."""
import json
import sys
from pathlib import Path
from resource_study import prepare, verify, PRIOR


def seed(root, evidence, home):
    prepare(root, evidence, home)
    parent = root / ".kuzushi/v3/campaigns"
    baseline = json.loads((parent / PRIOR / "plan.json").read_text())
    for index in range(150):
        identifier = "owned-history-" + str(index).zfill(3)
        plan = json.loads(json.dumps(baseline))
        plan.update({"campaignId": identifier, "batchId": identifier, "createdAtMs": index + 1})
        for job in plan["jobs"]:
            job["input"]["batchId"] = identifier
            job["input"]["logicalTrialId"] = identifier + "-" + job["jobId"]
        directory = parent / identifier
        directory.mkdir()
        (directory / "plan.json").write_text(json.dumps(plan))
    broken = parent / "owned-malformed-history"
    broken.mkdir()
    (broken / "plan.json").write_text("Labeled malformed history fixture")


def change_history(root, action):
    path = root / ".kuzushi/v3/campaigns"
    saved = path.with_name("campaigns-owned-saved")
    if action == "break-history":
        assert path.is_dir() and not saved.exists()
        path.rename(saved)
        path.write_text("Owned history read failure fixture")
    else:
        assert path.is_file() and saved.is_dir()
        path.unlink()
        saved.rename(path)


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    assert root == evidence / "fixture-target"
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage in ["break-history", "restore-history"]:
        change_history(root, stage)
    else:
        verify(root, evidence, stage)
