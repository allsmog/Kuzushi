"""Synthetic run artifacts for the offline revision-comparison UI journey."""
import json
import sys
from pathlib import Path


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n")


def finding(key, path):
    return {
        "fingerprint": key, "identityId": "fi_" + key,
        "title": "Synthetic fixture: " + key,
        "severity": "high", "filePath": path, "startLine": 1,
        "tool": "agentic-sast",
    }


def write_run(root, run, content_hash, findings):
    directory = root / ".kuzushi/v3/runs" / run
    write_json(directory / "run.json", {
        "runId": run, "kind": "tool", "status": "completed",
        "target": str(root), "startedAtUnix": 1,
        "targetGit": {"sha": "a" * 40, "branch": "synthetic-fixture", "dirty": True},
    })
    write_json(directory / "result.json", {
        "ok": True, "status": "completed", "summary": "Synthetic UI fixture",
        "data": {"treeHash": content_hash * 64},
    })
    write_json(directory / "findings.json", findings)
    return directory


def seed(root):
    seen = finding("seen-again", "src/present.rs")
    write_run(root, "fixture-base", "b", [seen,
        finding("not-observed", "src/absent.rs"),
        finding("not-reassessed", "outside/unknown.rs")])
    later = write_run(root, "fixture-later", "c", [seen])
    write_json(later / "phase-stages.jsonl", {
        "phase": "scan", "outcome": "completed", "runRefs": ["fixture-later"],
        "scan": {
            "scope": {"target": str(root), "paths": ["src"]},
            "plan": {"selection": "explicit", "engines": ["agentic-sast"]},
            "engines": [{"engine": "agentic-sast", "outcome": "complete"}],
            "findingDelta": {"added": 0, "updated": 1}, "durationMs": 1,
            "targetSnapshot": {"target": str(root), "revision": "a" * 40, "dirty": True},
        },
    })


if __name__ == "__main__":
    seed(Path(sys.argv[1]).resolve())
