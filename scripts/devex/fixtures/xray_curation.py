"""Owned inert reports and unapproved generation. Zero model or source execution."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def save(folder, name, value):
    (folder / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def hashes(root):
    paths = [root / "main.rs", *sorted((root / "x-ray").glob("*"))]
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "main.rs").write_text("// Owned inert metadata; never compiled or executed.\n")
    reports = root / "x-ray"
    reports.mkdir(exist_ok=True)
    for name, text in {
        "x-ray.md": "# Owned labeled report\n## X-Ray Verdict\nREADY\nThis is an unassessed stored claim over inert metadata.\n",
        "entry-points.md": "# Entry Points\n> Owned metadata | 1 entry point | 1 permissionless | 0 role-gated | 0 admin-only\n",
        "invariants.md": "# Invariants\n### G-1 Preserve the declared package name\n",
        "architecture.svg": '<svg xmlns="http://www.w3.org/2000/svg"><title>Owned labeled metadata</title></svg>\n',
    }.items():
        (reports / name).write_text(text)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    credentials = home / ".kuzushi/offline-oauth.json"
    credentials.write_text('{"openai-codex":{"access":"offline-fixture","expires":99999999999999}}')
    guard = evidence / "reject-provider.mjs"
    guard.write_text('import {appendFileSync} from "node:fs"; import {fileURLToPath} from "node:url"; globalThis.fetch = async () => { appendFileSync(fileURLToPath(new URL("provider-attempts.jsonl",import.meta.url)), "attempt\\n"); throw new Error("Unexpected model attempt in an unapproved audit"); };\n')
    repo = Path(__file__).resolve().parents[3]
    command = ["node", "--import", str(guard), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\nlanggraph_bridge_command = ' + json.dumps(command) + '\n[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\nallow_env_token = false\n')
    (evidence / "runtime-home.txt").write_text(str(home))
    save(evidence, "source-before", hashes(root))


def native(root, evidence, label, args, success=True):
    env = dict(os.environ, HOME=(evidence / "runtime-home.txt").read_text())
    for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "NODE_OPTIONS"]:
        env.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root), *args], env=env, capture_output=True, text=True, timeout=35)
    (evidence / (label + ".stderr.txt")).write_text(result.stderr)
    (evidence / (label + ".stdout.txt")).write_text(result.stdout)
    assert (result.returncode == 0) == success, (label, result.stderr)
    value = json.loads(result.stdout)
    save(evidence, label, value)
    return value


def check_catalog(root, evidence):
    core = native(root, evidence, "default-catalog", ["tools", "--json"])
    all_tools = native(root, evidence, "all-catalog", ["tools", "--all", "--json"])
    assert any(tool["name"] == "x-ray:read" for tool in core)
    assert not any(tool["name"] == "x-ray:run" for tool in core)
    generator = next(tool for tool in all_tools if tool["name"] == "x-ray:run")
    assert generator["maturity"] == "labs" and generator["phase_result"] is False
    assert generator["approval"] == "explicit" and generator["effect"] == "target-write"
    assert any(option["name"] == "allowanceRef" for option in generator["options"])
    refused = native(root, evidence, "unapproved-generation", ["run", "x-ray:run", "--input", "{}"], False)
    assert refused["status"] == "blocked", refused
    assert "approved investigation allowance before model work" in json.dumps(refused)
    verify(root, evidence)


def verify(root, evidence):
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    assert not (evidence / "provider-attempts.jsonl").exists()
    save(evidence, "verified", {"modelCalls": 0, "sourceExecuted": False, "reportsUnchanged": True,
        "generationCoreDefault": False, "generationPhaseResult": False, "readerCore": True})


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    evidence.mkdir(parents=True, exist_ok=True)
    if stage == "seed": seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "catalog": check_catalog(root, evidence)
    else: verify(root, evidence)
