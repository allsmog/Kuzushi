"""Owned inert metadata. This journey edits settings and never dispatches tools."""
import hashlib
import json
import sys
from pathlib import Path


def source_hashes(root):
    files = [path for path in root.rglob("*") if path.is_file()
             and not {".git", ".kuzushi"}.intersection(path.relative_to(root).parts)]
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(files)}


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "README.md").write_text("# Owned options fixture\nInert metadata, never built or executed.\n")
    (root / "main.rs").write_text("// Owned inert metadata. No executable source.\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("")
    (evidence / "home.txt").write_text(str(home))
    (evidence / "source-before.json").write_text(json.dumps(source_hashes(root)))
    (evidence / "multiline.txt").write_text('Operator α\nInspect "declared metadata"\nKeep this draft.')


def verify(root, evidence, stage):
    home = Path((evidence / "home.txt").read_text())
    path = home / ".kuzushi/v3/options.json"
    store = json.loads(path.read_text()) if path.exists() else {"bindings": {}}
    if stage == "session":
        assert not any("sampleLimit" in values for values in store["bindings"].values())
    else:
        assert store["bindings"]["global/tool/context:build"]["sampleLimit"] == 9
    assert not any("CONTEXT_PROMPT" in values for values in store["bindings"].values())
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    assert not list((root / ".kuzushi/v3/runs").glob("*/run.json"))
    assert not list((root / ".kuzushi/v3/campaigns").glob("**/jobs/*.json"))
    (evidence / (stage + "-verified.json")).write_text(json.dumps({
        "sourceUnchanged": True, "dispatchedJobs": 0,
        "authenticatedSourceFiles": sorted(source_hashes(root)),
        "persistentSampleLimit": None if stage == "session" else 9,
        "multilineDraftPersisted": False,
    }, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, stage)
