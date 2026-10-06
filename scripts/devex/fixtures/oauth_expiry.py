"""Offline OAuth refresh failure through real prepared dispatch. No inference."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path


def seed(root, evidence, home):
    repo = Path(__file__).resolve().parents[3]
    credential = home / ".kuzushi/oauth-credentials.json"
    credential.parent.mkdir(parents=True, exist_ok=True)
    credential.write_text(json.dumps({"openai-codex": {
        "access": "expired-offline-tui-fixture", "refresh": "invalid-refresh-fixture", "expires": 1,
    }}) + "\n")
    credential.chmod(0o600)
    marker = evidence / "auth-requests.jsonl"
    hook = evidence / "auth-transport-fixture.mjs"
    hook.write_text("""
import { appendFileSync } from 'node:fs';
process.env.NODE_OPTIONS = '--import=' + import.meta.url;
globalThis.fetch = async (url) => {
  if (url !== 'https://auth.openai.com/oauth/token') throw new Error('Unexpected network request');
  appendFileSync(MARKER, JSON.stringify({endpoint:'oauth/token'})+'\\n');
  return new Response(JSON.stringify({error:'invalid_grant'}), {status:400});
};
""".replace("MARKER", json.dumps(str(marker))))
    command = ["node", "--import", str(hook), str(repo / "scripts/langgraph-bridge.mjs")]
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-6-luna"\n[runtime]\nthinking_level = "low"\n'
                      + 'langgraph_bridge_command = ' + json.dumps(command) + '\n'
                      + '[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credential)) + '\n'
                      + 'allow_env_token = false\n')
    (evidence / "runtime-source.sha256").write_text(hashlib.sha256((repo / "scripts/langgraph-bridge/model.mjs").read_bytes()).hexdigest() + "\n")


def verify(root, evidence):
    state = root / ".kuzushi/v3"
    run_paths = list((state / "runs").glob("*/run.json"))
    runs = [json.loads(path.read_text()) for path in run_paths]
    contexts = [run for run in runs if run.get("tool") == "threat-model:build"]
    assert len(contexts) == 1
    assert contexts[0]["status"] == "failed", contexts[0]
    requests = [json.loads(line) for line in (evidence / "auth-requests.jsonl").read_text().splitlines()]
    assert requests == [{"endpoint": "oauth/token"}]
    with sqlite3.connect((state / "index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        assert connection.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 0
        assert connection.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 1
        approval = json.loads(connection.execute("select approval_json from investigation_allowance_revisions order by revision desc limit 1").fetchone()[0])
        assert approval["limits"] == {"maxProviderCalls": 8, "protectedReviewCalls": 2}
        (evidence / "open-context.txt").write_text("campaign " + approval["workPlan"]["campaignId"])
    (evidence / "offline-expiry-verified.json").write_text(json.dumps({"contextAttempts": 1, "inferenceRequests": 0, "providerReservations": 0, "fakeRefreshRequests": 1, "liveNetworkRequests": 0}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "verify":
        verify(root, evidence)
