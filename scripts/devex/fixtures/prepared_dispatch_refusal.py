"""Owned observations, denied model work, and a transport with no network fallback."""
import json
import sys
from pathlib import Path

from review_navigation import seed as seed_observations, verify as verify_observations


def seed(root, evidence, home):
    seed_observations(root, evidence, home)
    provider = evidence / "deny-provider.mjs"
    provider.write_text('import { appendFileSync } from "node:fs";\n'
                        + 'globalThis.fetch = async () => {\n'
                        + '  appendFileSync(' + json.dumps(str(evidence / "unexpected-requests.txt")) + ', "request\\n");\n'
                        + '  throw new Error("Owned refusal fixture has no network fallback");\n};\n')
    credentials = home / ".kuzushi/oauth-credentials.json"
    credentials.parent.mkdir(parents=True, exist_ok=True)
    credentials.write_text(json.dumps({"openai-codex": {"access": "offline-refusal-fixture", "expires": 99999999999999}}))
    credentials.chmod(0o600)
    bridge = Path(__file__).resolve().parents[3] / "scripts/langgraph-bridge.mjs"
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n'
                      + 'langgraph_bridge_command = ' + json.dumps(["node", "--import", str(provider), str(bridge)]) + '\n'
                      + '[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\nallow_env_token = false\n')


def verify(root, evidence, stage, tool="triage:run"):
    verify_observations(root, evidence)
    assert not (evidence / "unexpected-requests.txt").exists(), "Unapproved work reached transport"
    runs = []
    for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
        summary = json.loads(path.read_text())
        if summary.get("tool") == tool:
            runs.append((path.parent, summary))
    assert len(runs) == 1, "Reading or restart changed the number of refused jobs"
    run, summary = runs[0]
    result = json.loads((run / "result.json").read_text())
    assert result["status"] == "blocked", result
    assert not summary.get("llmCalls"), "A blocked job claimed a model call"
    assert "no model request started" in json.dumps(result)
    (evidence / "replay-command.txt").write_text("replay " + run.name)
    (evidence / (stage + "-refusal-check.json")).write_text(json.dumps({
        "runId": run.name, "tool": tool, "status": "blocked", "providerRequests": 0,
        "observations": 3, "decisions": 0, "sourceUnchanged": True,
        "sourceExecuted": False, "allowanceApproved": False,
    }, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    evidence.mkdir(parents=True, exist_ok=True)
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, stage)
