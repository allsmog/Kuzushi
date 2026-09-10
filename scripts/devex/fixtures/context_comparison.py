"""Import two labeled fixture contexts and execute source-only offline CLI scans."""
import json
import os
import sys
import subprocess
from pathlib import Path


def run_tool(binary, root, evidence, label, tool, value, run_id=None):
    command = [binary, "--target", str(root), "run", tool, "--input", "-"]
    if run_id:
        command += ["--run-id", run_id]
    result = subprocess.run(command, input=json.dumps(value), text=True,
                            capture_output=True, timeout=45, check=False)
    (evidence / (label + ".stdout.json")).write_text(result.stdout)
    (evidence / (label + ".stderr.txt")).write_text(result.stderr)
    if result.returncode:
        raise RuntimeError(f"Offline fixture {label} failed; inspect its stderr receipt")
    output = json.loads(result.stdout)
    if output.get("ok") is False or output.get("status") == "failed":
        raise RuntimeError(f"Offline fixture {label} returned a failed tool result")


def import_context(binary, root, evidence, label):
    document = {
        "version": "1", "methodology": "stride", "title": "Offline fixture " + label,
        "dfd": {"nodes": [{"id": "app", "type": "process", "name": label,
                            "description": "Labeled offline context fixture", "trustZone": "internal"}],
                "flows": [], "trustBoundaries": []},
        "threats": [], "summary": {},
    }
    run_tool(binary, root, evidence, "import-" + label, "threat-model:import",
             {"document": document, "label": label, "activate": True})
    manifest = root / ".kuzushi/threat-models/manifest.json"
    return json.loads(manifest.read_text())["active"]


def seed(root, evidence):
    binary = os.environ["KUZUSHI_NATIVE_BIN"]
    evidence.mkdir(parents=True, exist_ok=True)
    first = import_context(binary, root, evidence, "alpha")
    second = import_context(binary, root, evidence, "beta")
    if first == second:
        raise RuntimeError("Fixture contexts must have distinct immutable identities")
    for run_id, reference in [("context-base", first), ("context-later", second)]:
        run_tool(binary, root, evidence, run_id, "sast:scan", {
            "taskMode": "manual", "tasks": ["secret-scan"], "threatModelRef": reference,
            "triage": False, "verify": False, "autoPatch": False,
        }, run_id)
        saved = json.loads((root / ".kuzushi/v3/runs" / run_id / "scan-input.json").read_text())
        if saved["threatModelRef"] != reference:
            raise RuntimeError("Scan receipt changed the explicitly selected context")
    active = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())["active"]
    if active != second:
        raise RuntimeError("A scan changed the globally active threat model")
    (evidence / "context-receipt.json").write_text(json.dumps({
        "status": "passed", "base": first, "later": second, "activeAfterScans": active,
        "runs": ["context-base", "context-later"], "providerCalls": 0,
        "engine": "secret-scan", "source": "labeled offline fixture",
    }, indent=2) + "\n")


if __name__ == "__main__":
    seed(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
