"""Synthetic persisted allowance refusal for a model-free TUI recovery audit."""
import json
import sys
from pathlib import Path


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n")


def seed(root):
    run_id = "fixture-allowance-stop"
    directory = root / ".kuzushi/v3/runs" / run_id
    message = "Investigation allowance refused this request; finish and report or review the remaining work"
    metadata = {"errorClass": "allowance_refused"}
    context = {
        "failedStage": "agentic-sast:scan", "cause": message,
        "whatFailed": "Synthetic fixture: one discovery request was refused.",
        "artifactsAvailable": [], "missingArtifacts": ["findings.json"],
        "allowedProofLevel": "source-analysis-only; scan incomplete",
        "nextFilesOrArtifactsToInspect": ["failures.json"],
        "recoveryOptions": [
            "Finish and report the completed and partial work.",
            "Review remaining work and approve a specific allowance revision before another model request.",
            "Preserve unresolved reservations; this failure does not establish zero cost.",
        ],
        "fallbackPrompt": "Synthetic fixture. Review the saved evidence and allowance before proposing further work.",
        "claimsForbidden": ["scan complete", "zero cost"],
        "runtimeFailure": metadata, "model": "openai-codex:gpt-5.5",
    }
    write_json(directory / "run.json", {
        "runId": run_id, "kind": "tool", "status": "failed",
        "target": str(root), "startedAtUnix": 1,
    })
    write_json(directory / "failures.json", {
        "runId": run_id, "status": "failed", "failures": [{
            "tool": "agentic-sast:scan", "status": "failed", "error": message,
            "errorClass": "allowance_refused", "runtimeFailure": metadata,
            "model": "openai-codex:gpt-5.5", "agentThreadContext": context,
        }],
    })
    (directory.parent.parent / "latest").write_text(run_id + "\n")


if __name__ == "__main__":
    seed(Path(sys.argv[1]).resolve())
