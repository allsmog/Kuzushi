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
    return output


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


def git(root, *args):
    command = ["git", "-C", str(root), "-c", "core.hooksPath=/dev/null",
               "-c", "commit.gpgSign=false", "-c", "user.name=Kuzushi fixture",
               "-c", "user.email=fixture@example.invalid", *args]
    return subprocess.run(command, check=True, text=True, capture_output=True,
                          timeout=20).stdout.strip()


def commit_source(root, label):
    git(root, "add", "--all")
    git(root, "commit", "--quiet", "-m", label)
    return git(root, "rev-parse", "HEAD")


def scan_context(binary, root, evidence, run_id, reference):
    output = run_tool(binary, root, evidence, run_id, "sast:scan", {
        "taskMode": "manual", "tasks": ["secret-scan"], "threatModelRef": reference,
        "triage": False, "verify": False, "autoPatch": False,
    }, run_id)
    run = root / ".kuzushi/v3/runs" / run_id
    saved = json.loads((run / "scan-input.json").read_text())
    summary = json.loads((run / "run.json").read_text())
    observations = json.loads((run / "findings.json").read_text())
    if saved["threatModelRef"] != reference:
        raise RuntimeError("Scan input changed the explicitly selected context")
    for summary_key, ref_key in [("threatModelSha256", "sha256"),
                                 ("threatModelId", "modelId"),
                                 ("threatModelRevisionId", "revisionId")]:
        expected = reference[ref_key] if reference else None
        if summary.get(summary_key) != expected:
            raise RuntimeError("Run summary misattributed the selected context")
    if not observations or observations != output["data"]["coreFindings"]:
        raise RuntimeError("Discovery snapshot must preserve the real fixture observations")
    return {"runId": run_id, "git": summary["targetGit"],
            "treeHash": output["data"]["treeHash"], "findings": len(observations)}


def seed(root, evidence):
    binary = os.environ["KUZUSHI_NATIVE_BIN"]
    evidence.mkdir(parents=True, exist_ok=True)
    git(root, "init", "--quiet", "--initial-branch=main")
    (root / ".gitignore").write_text("# Kuzushi maintains its own state ignore rules.\n")
    commit_source(root, "Initial labeled source fixture")
    first = import_context(binary, root, evidence, "alpha")
    second = import_context(binary, root, evidence, "beta")
    if first == second:
        raise RuntimeError("Fixture contexts must have distinct immutable identities")
    base = scan_context(binary, root, evidence, "context-base", first)
    note = root / "revision-note.txt"
    note.write_text("Labeled second source revision; scanner candidate is unchanged.\n")
    commit_source(root, "Add source revision note")
    later = scan_context(binary, root, evidence, "context-later", second)
    note.write_text("Labeled uncommitted source change; scanner candidate is unchanged.\n")
    dirty = scan_context(binary, root, evidence, "context-dirty", None)
    if base["git"]["sha"] == later["git"]["sha"] or base["treeHash"] == later["treeHash"]:
        raise RuntimeError("Different commits must retain distinct source identities")
    if dirty["git"]["sha"] != later["git"]["sha"] or dirty["treeHash"] == later["treeHash"]:
        raise RuntimeError("Uncommitted edits must change content identity at the same SHA")
    if not dirty["git"]["dirty"] or later["git"]["dirty"]:
        raise RuntimeError("Source receipts must distinguish clean and dirty worktrees")
    active = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())["active"]
    if active != second:
        raise RuntimeError("A scan changed the globally active threat model")
    (evidence / "context-receipt.json").write_text(json.dumps({
        "status": "passed", "base": first, "later": second, "activeAfterScans": active,
        "runs": [base, later, dirty], "providerCalls": 0,
        "engine": "secret-scan", "source": "labeled offline fixture",
    }, indent=2) + "\n")


if __name__ == "__main__":
    seed(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
