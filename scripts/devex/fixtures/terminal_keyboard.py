"""Keyboard protocol checks over inert owned source, with no model work."""
import hashlib
import json
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def source_hash(root):
    return hashlib.sha256((root / "README.md").read_bytes()).hexdigest()


def seed(root, evidence, home):
    assert not (evidence / "keyboard-source-before.json").exists()
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "README.md").write_text("# Owned inert keyboard fixture\nNo target source is executed.\n")
    save(evidence, "keyboard-source-before", {"sha256": source_hash(root)})
    (evidence / "literal-paste.txt").write_text("first α\n[4~ literal\nlast β\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')


def inspect(root, evidence, stage):
    assert source_hash(root) == json.loads((evidence / "keyboard-source-before.json").read_text())["sha256"]
    assert not list((root / ".kuzushi/v3/runs").glob("*/result.json"))
    paths = list(evidence.glob("*-" + stage + ".txt"))
    assert len(paths) == 1
    text = paths[0].read_text()
    if stage == "escape-end":
        assert "[4~" not in text.splitlines()[-1]
        assert "describe what to map" in text.splitlines()[-1]
    elif stage == "literal-inspection":
        assert "[4~ literal" in text
        assert "first α" in text and "last β" in text
    elif stage == "typed-literal":
        assert "› [4~" in text.splitlines()[-1]
    save(evidence, stage + "-verified", {"sourceUnchanged": True, "runResults": 0,
        "providerRequests": 0, "targetSourceExecuted": False, "capture": paths[0].name})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        inspect(root, evidence, stage)
