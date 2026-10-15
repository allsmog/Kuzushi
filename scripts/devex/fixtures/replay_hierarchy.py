"""Read an existing owned synthetic receipt. Never invoke a scanner or model."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def git(root, *arguments):
    return subprocess.check_output(["git", "-C", str(root), *arguments], text=True).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_files(root):
    return {name: digest(root / name) for name in git(root, "ls-files").splitlines()}


def findings(root):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "findings", "--json"], capture_output=True, text=True, check=True, timeout=20)
    return json.loads(result.stdout)


def seed(root, evidence):
    assert root.name == "fixture-target"
    assert "kuzushi-tui-integration-20261012" in root.parts
    assert git(root, "rev-parse", "HEAD") == "b8d88e65d643dd7b113e1a18e27a83da9d89ac65"
    candidates = []
    receipts = {}
    for path in (root / ".kuzushi/v3/runs").glob("*/result.json"):
        receipts[str(path.relative_to(root))] = digest(path)
        run = json.loads((path.parent / "run.json").read_text())
        if run.get("tool") == "codeql:scan" and run.get("status") == "partial":
            result = json.loads(path.read_text())
            assert result["data"]["count"] == 1
            assert "Labeled owned source observation" in json.dumps(result)
            candidates.append(run["runId"])
    assert len(candidates) == 1
    (evidence / "replay.txt").write_text("replay " + candidates[0])
    before = {"sha": git(root, "rev-parse", "HEAD"), "sources": source_files(root),
        "receipts": receipts, "findings": findings(root)}
    (evidence / "before.json").write_text(json.dumps(before, indent=2) + "\n")


def verify(root, evidence, stage):
    before = json.loads((evidence / "before.json").read_text())
    assert git(root, "rev-parse", "HEAD") == before["sha"]
    assert source_files(root) == before["sources"]
    assert findings(root) == before["findings"]
    for path, expected in before["receipts"].items():
        assert digest(root / path) == expected
    (evidence / (stage + "-check.json")).write_text(json.dumps({"providerCalls": 0,
        "scannerCalls": 0, "sourceExecution": False, "originalReceiptsPreserved": True,
        "findingsPreserved": True, "sourcePreserved": True}, indent=2) + "\n")


if __name__ == "__main__":
    stage, root, evidence = sys.argv[1:]
    root, evidence = Path(root).resolve(), Path(evidence).resolve()
    if stage == "seed":
        seed(root, evidence)
    else:
        verify(root, evidence, stage)
