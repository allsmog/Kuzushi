"""Owned inert repository through actual OAuth. Never imports target source."""
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

MODEL = "openai-codex:gpt-6-luna"
INVESTIGATION = "live-owned-investigation-20261010"
CONTEXT = "live-owned-map-20261010"
SCAN = "live-owned-scans-20261010"
OWNER = Path("/Users/shayaunnejad")
FIXTURE = Path("/private/tmp/kuzushi-live-owned-investigation-20261010")
CONTROL = FIXTURE / "control"


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def native(root, evidence, name, tool, value):
    env = dict(os.environ, HOME=str(FIXTURE / "home"))
    for key in ["NODE_OPTIONS", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
        env.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", tool, "--input", json.dumps(value)], env=env, capture_output=True, text=True, timeout=45)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, (name, result.stderr)
    receipt = json.loads(result.stdout)
    save(evidence, name, receipt)
    return receipt["data"]


def sources(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["greeting.py", "public-example.env", "README.md", ".gitignore"]}


def seed(root, evidence, home):
    assert root == FIXTURE / "target" and home == FIXTURE / "home"
    assert not (CONTROL / "source-before.json").exists(), "Live fixture already prepared; reuse its source, plans and accounting"
    root.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)
    if not (root / ".git").exists():
        subprocess.run(["git", "init", "--initial-branch=main", str(root)], capture_output=True, check=True)
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "greeting.py").write_text('"""Owned static fixture. Never executed."""\ndef greeting(name: str) -> str:\n    return "Hello, " + name\n')
    (root / "public-example.env").write_text("# Public documentation example, not an active credential.\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    (root / "README.md").write_text("# Owned inert greeting\nA pure function formats a greeting. No server, persistence, network or executable entrypoint is supplied. The environment file holds a public example string for human false-positive triage. Source is never executed.\n")
    (root / ".gitignore").write_text("# Workspace state manages its own ignore policy.\n")
    git(root, "config", "user.name", "Owned test fixture")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "config", "commit.gpgsign", "false")
    git(root, "symbolic-ref", "HEAD", "refs/heads/main")
    git(root, "add", "greeting.py", "public-example.env", "README.md", ".gitignore")
    git(root, "commit", "-m", "test: record owned investigation fixture")
    credentials = OWNER / ".kuzushi/oauth-credentials.json"
    assert credentials.is_file(), "Renew stored OAuth using the existing flow; do not invent credentials"
    repo = Path(__file__).resolve().parents[3]
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = ' + json.dumps(MODEL) + '\n[runtime]\nthinking_level = "low"\nlanggraph_bridge_command = '
        + json.dumps(["node", str(repo / "scripts/langgraph-bridge.mjs")])
        + '\n[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\nallow_env_token = false\n')
    operator_config = OWNER / ".kuzushi/v3/config.toml"
    save(evidence, "source-before", {"sha": git(root, "rev-parse", "HEAD"), "files": sources(root),
        "operatorConfigSha256": hashlib.sha256(operator_config.read_bytes()).hexdigest()})
    prepare_drafts(root, evidence)


def prepare_drafts(root, evidence):
    scope = native(root, evidence, "scope-draft", "pack:scopes", {})
    accepted = native(root, evidence, "scope-accepted", "pack:scopes", {"operation":"accept",
        "proposalRef":scope["reference"], "acknowledgements":{"inventoryLimitations":True,"exclusions":False,"overlappingDiscovery":False}})
    save(evidence, "scope-ref", {"proposal":accepted["reference"], "scopeId":"repository"})
    native(root, evidence, "context-draft", "campaign:context-study", {"campaignId":CONTEXT,
        "investigationId":INVESTIGATION, "preparationJobs":[{"tool":"context:build","input":{"enrichment":False}},
        {"tool":"entry-points:extract","input":{}}], "contextInput":{"model":MODEL,
        "contextLimit":5,"maxSourceBytes":4096,"maxElements":8,"maxThreats":4,"maxOutputTokens":1024}})
    (evidence / "context-command.txt").write_text("campaign " + CONTEXT)


def settled_jobs(root, campaign):
    file = root / ".kuzushi/v3/campaigns" / campaign / "queue.json"
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        if file.exists():
            jobs = json.loads(file.read_text())["jobs"]
            if all(job["state"] not in ["planned", "running"] for job in jobs.values()):
                return jobs
        time.sleep(1)
    raise RuntimeError("Existing jobs are not terminal. Inspect their process and receipts; do not restart.")


def invariant(root, evidence):
    before = json.loads((CONTROL / "source-before.json").read_text())
    assert git(root, "rev-parse", "HEAD") == before["sha"]
    assert sources(root) == before["files"]
    assert not git(root, "status", "--porcelain=v1")
    assert hashlib.sha256((OWNER / ".kuzushi/v3/config.toml").read_bytes()).hexdigest() == before["operatorConfigSha256"]


def context_done(root, evidence):
    jobs = settled_jobs(root, CONTEXT)
    assert len(jobs) == 3 and all(row["state"] == "completed" and row["attempts"] == 1 for row in jobs.values()), jobs
    result = json.loads((root / ".kuzushi/v3/runs" / jobs["context-001"]["runId"] / "result.json").read_text())
    reference = result["data"]["modelRef"]
    save(evidence, "generated-context", native(root, evidence, "context-read", "threat-model:read", {"threatModelRef":reference}))
    save(evidence, "context-reference", reference)
    save(CONTROL, "context-reference", reference)
    invariant(root, evidence)


def prepare_scan(root, evidence):
    invariant(root, evidence)
    scan = native(root, evidence, "scan-draft", "campaign:study", {"campaignId":SCAN,"investigationId":INVESTIGATION,
        "trials":3,"workers":1,"scanInput":{"taskMode":"manual","tasks":["agentic","secret-scan"],
        "model":MODEL,"mode":"whitebox-static","thinkingLevel":"low","mcps":False,
        "agenticMaxModelTurns":2,"maxInventoryFiles":8,"maxBytesPerFile":1024,"maxFindings":3,
        "triage":False,"verify":False,"autoPatch":False,"scanScopeRef":json.loads((CONTROL / "scope-ref.json").read_text()),
        "threatModelRef":json.loads((CONTROL / "context-reference.json").read_text())}})
    plan = json.loads((root / ".kuzushi/v3/campaigns" / SCAN / "plan.json").read_text())
    assert len(plan["jobs"]) == 3 and plan["workers"] == 1
    assert all(job["input"]["agenticMaxModelTurns"] == 2 for job in plan["jobs"])
    (evidence / "scan-command.txt").write_text("campaign " + SCAN)
    invariant(root, evidence)


def verify(root, evidence, stage):
    invariant(root, evidence)
    if stage == "scan-done":
        jobs = settled_jobs(root, SCAN)
        save(evidence, "observed-scan-jobs", jobs)
        assert len(jobs) == 3 and all(job["attempts"] <= 1 for job in jobs.values())
    status = native(root, evidence, "allowance-" + stage, "campaign:allowance", {"investigationId":INVESTIGATION})
    allowance = status["allowance"]
    assert allowance["limits"] == {"maxProviderCalls":11,"protectedReviewCalls":2}
    assert allowance["committedCalls"] <= 9 and allowance["reviewCalls"] == 0
    accounting = {key:allowance[key] for key in ["committedCalls","unresolvedCalls","reviewCalls"]}
    if stage == "scan-done":
        save(CONTROL, "post-scan-accounting", accounting)
    else:
        assert accounting == json.loads((CONTROL / "post-scan-accounting.json").read_text())
    save(evidence, stage + "-verified", {"sourceUnchanged":True,"realSourceCommit":git(root,"rev-parse","HEAD"),
        "operatorConfigUnchanged":True,"liveCommittedCalls":allowance["committedCalls"],"limits":allowance["limits"]})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "prepare-drafts":
        invariant(root, evidence)
        prepare_drafts(root, evidence)
    elif stage == "context-done":
        context_done(root, evidence)
    elif stage == "prepare-scan":
        prepare_scan(root, evidence)
    else:
        verify(root, evidence, stage)
