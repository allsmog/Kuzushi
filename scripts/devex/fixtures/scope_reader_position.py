"""Portable owned fixture for pinned scope reading. No model or source execution."""
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SOURCE = {
    "apps/control-panel/main.rs": "// Inert scope-reading fixture. Never executed.\n",
    "README.md": "Owned scope-reading fixture, not a security finding.\n",
    " root note.md": "An intentionally space-prefixed fixture filename.\n",
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create_draft(root, evidence, home):
    scopes = [
        {"id": "client", "name": "Control panel client", "paths": ["apps/control-panel"],
         "rationale": "Inspect the owned client fixture as one proposed component.",
         "sharedDependencies": [], "openQuestions": ["Which interfaces need operator context?"]},
        {"id": "notes", "name": "認証 service with a deliberately long boundary label",
         "paths": ["README.md", " root note.md"],
         "rationale": "Keep the two owned notes together for this reader fixture.",
         "sharedDependencies": [], "openQuestions": []},
    ]
    value = {"operation": "create", "draft": {"schemaVersion": 1, "scopes": scopes,
        "sharedScope": None, "sharedDiscovery": False, "exclusions": []}}
    env = dict(os.environ, HOME=str(home))
    for name in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KUZUSHI_MODEL", "NODE_OPTIONS"]:
        env.pop(name, None)
    env["NODE_OPTIONS"] = "--import=" + str(REPO / "scripts/devex/fixtures/deny_provider_transport.mjs")
    env["KUZUSHI_TEST_DENIED_FETCH_LOG"] = str(evidence / "denied-fetch.jsonl")
    command = [os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root),
        "run", "pack:scopes", "--input", json.dumps(value)]
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=90)
    (evidence / "create-stdout.json").write_text(result.stdout)
    (evidence / "create-stderr.log").write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["data"]


def proposal_hashes(root):
    return {str(path.relative_to(root)): sha(path)
        for path in (root / ".kuzushi/v3/scan-scopes").rglob("*.json")}


def prepare(root, evidence, home):
    for directory in [root, home]:
        subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(directory)],
            check=True, capture_output=True, timeout=20)
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    for name, text in SOURCE.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    review = create_draft(root, evidence, home)
    assert review["coverage"]["enumeratedFiles"] == 3
    assert review["coverage"]["uncoveredFiles"]["total"] == 0
    assert review["record"].get("acceptance") is None
    proof = {"source": {name: sha(root / name) for name in SOURCE},
        "proposals": proposal_hashes(root), "reference": review["reference"]}
    (evidence / "state-before.json").write_text(json.dumps(proof, indent=2) + "\n")
    verify(root, evidence, "prepared")


def reading_ranges(evidence):
    results = []
    for label in ["reader-size-160x48", "reader-size-120x36", "reader-size-96x89",
        "reader-size-80x24", "reader-size-60x20", "reader-size-40x12",
        "reader-paged-40x12", "reader-end-40x12", "reader-home-40x12", "unicode-end-40x12"]:
        path, = evidence.glob("*-" + label + ".txt")
        header = path.read_text().splitlines()[1].strip().strip("│").strip()
        found = re.search(r"(\d+)-(\d+)/(\d+)$", header)
        assert found, (label, header)
        first, last, total = map(int, found.groups())
        assert 1 <= first <= last <= total
        if label.startswith("reader-size-"):
            assert header.startswith("Control panel client · ")
        if label == "reader-paged-40x12":
            assert (first, last) == (7, 12)
        if "-end-" in label:
            assert last == total
        if "-home-" in label:
            assert first == 1
        if label.startswith("unicode-"):
            assert header.startswith("認証 service")
        results.append({"snapshot": path.name, "header": header,
            "firstLine": first, "lastLine": last, "totalLines": total})
    (evidence / "reading-ranges.json").write_text(json.dumps(results, indent=2) + "\n")


def verify(root, evidence, stage):
    before = json.loads((evidence / "state-before.json").read_text())
    assert all(sha(root / name) == value for name, value in before["source"].items())
    assert proposal_hashes(root) == before["proposals"]
    state = root / ".kuzushi/v3"
    records = list((state / "scan-scopes/revisions").glob("*.json"))
    assert len(records) == 1 and json.loads(records[0].read_text()).get("acceptance") is None
    assert not list((state / "campaigns").glob("*/plan.json"))
    assert not (evidence / "denied-fetch.jsonl").exists()
    with sqlite3.connect((state / "index.sqlite3").as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute('select count(*) from "' + name + '"').fetchone()[0]
            for name in tables if name.startswith("investigation_")
            or name in ["finding_observations", "review_decisions"]}
        assert not any(counts.values()), counts
    for path in (state / "runs").glob("*/run.json"):
        record = json.loads(path.read_text())
        assert not record.get("llmCalls") and not record.get("llm_calls")
    if stage != "prepared":
        reading_ranges(evidence)
    proof = {"sourceFilesUnchanged": 3, "scopeRevisions": 1, "acceptedScopes": 0,
        "campaignPlans": 0, "providerRequests": 0, "ledgerCounts": counts,
        "sourceExecuted": False, "portableFixture": True}
    (evidence / (stage + "-check.json")).write_text(json.dumps(proof, indent=2) + "\n")


if __name__ == "__main__":
    target, artifact, operator_home = [Path(value).resolve() for value in sys.argv[1:4]]
    action = sys.argv[4]
    prepare(target, artifact, operator_home) if action == "prepare" else verify(target, artifact, action)
