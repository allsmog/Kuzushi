"""Historical source selection through real dispatch and intercepted transport."""
import hashlib
import os
import subprocess
import json
import shutil
import sys
from pathlib import Path

import lesson_generation

HISTORICAL = {"service.txt": "HISTORICAL_SERVICE: callers supply their tenant.\n",
              "policy.txt": "HISTORICAL_POLICY: compare the owner with the caller.\n"}
SELECTED = ["service.txt", "policy.txt", "missing.txt"]


def seed(root, evidence, home):
    root.mkdir(parents=True, exist_ok=True)
    assert root.name == "fixture-target", "Use the owned journey fixture"
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    for path, text in HISTORICAL.items():
        (root / path).write_text(text)
    env = dict(os.environ, KUZUSHI_LESSON_SUPPORT_FIXTURE_OUT=str(root))
    result = subprocess.run([os.environ["KUZUSHI_LESSON_SUPPORT_TEST_BIN"], "--exact",
        "capabilities::finding_lessons::tests::native_fixture::prepare_native_historical_lesson_fixture",
        "--ignored", "--nocapture"], env=env, capture_output=True, text=True, timeout=45, check=True)
    (evidence / "preparation.log").write_text(result.stdout + result.stderr)
    lesson_generation.seed(root, evidence, home, prepared=True)
    (root / "service.txt").write_text("CURRENT_ONLY: this later text must never enter the lesson.\n")
    (root / "policy.txt").unlink()
    (evidence / "provider.mjs").rename(evidence / "provider-base.mjs")
    shutil.copyfile(Path(__file__).with_name("lesson_support_provider.mjs"), evidence / "provider.mjs")


def verify(root, evidence, stage):
    lesson_generation.verify(root, evidence, stage)
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    plan = next(plan for plan in plans if plan.get("tool") == "findings:lesson-generate")
    frozen = plan["jobs"][0]["input"]
    assert frozen["sourceEvidenceFiles"] == SELECTED
    reference = frozen["sourceEvidenceRef"]
    digest = reference.removeprefix("lesson-source:")
    assert len(digest) == 64 and reference.startswith("lesson-source:")
    paths = list((root / ".kuzushi/v3/objects").rglob(digest))
    assert len(paths) == 1, paths
    bundle_bytes = paths[0].read_bytes()
    bundle = json.loads(bundle_bytes)
    assert bundle["selectedPaths"] == SELECTED
    assert bundle["origin"] == frozen["originRef"]
    assert [item["path"] for item in bundle["supporting"]] == SELECTED
    assert [item["text"] for item in bundle["supporting"]] == [*HISTORICAL.values(), None]
    assert bundle["supporting"][-1]["status"] == "not_recorded"
    assert all(item["currentSourceRead"] is False for item in bundle["supporting"])
    included = sum(len(item["text"].encode()) for item in [bundle["primary"], *bundle["supporting"]] if item["text"] is not None)
    assert included <= frozen["maxSourceBytes"]
    assert "CURRENT_ONLY" not in bundle_bytes.decode()
    if stage != "draft":
        calls = [json.loads(line) for line in (evidence / "supporting-calls.jsonl").read_text().splitlines()]
        assert len(calls) == 1 and calls[0]["liveProviderRequests"] == 0
    (evidence / (stage + "-support-check.json")).write_text(json.dumps({
        "stage": stage, "sourceEvidenceRef": reference, "bundleSha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "selectedPaths": SELECTED, "includedHistoricalBytes": included, "checkoutSubstituted": False,
        "deletedHistoricalFileIncluded": True, "missingFileDisclosed": True, "liveProviderRequests": 0,
    }, indent=2) + "\n")


if __name__ == "__main__":
    action, target, output, *homes = sys.argv[1:]
    root, evidence = Path(target).resolve(), Path(output).resolve()
    if action == "seed":
        seed(root, evidence, Path(homes[0]).resolve())
    else:
        verify(root, evidence, action)
