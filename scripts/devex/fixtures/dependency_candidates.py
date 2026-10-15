"""Local candidate coverage and catalog reading on inert owned manifests."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def native(root, evidence, label, args):
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root), *args],
                            capture_output=True, text=True, timeout=30)
    (evidence / (label + ".stdout.json")).write_text(result.stdout)
    (evidence / (label + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def source_identity(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ["package.json", "service/go.mod", "README.md"]}


def seed(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "README.md").write_text("Owned inert manifest inventory fixture.\n")
    (root / "package.json").write_text(json.dumps({"name": "owned-fixture",
        "dependencies": {"owned-package": "1.0.0"}}) + "\n")
    (root / "service").mkdir(exist_ok=True)
    (root / "service/go.mod").write_text("module example.invalid/owned\nrequire example.invalid/library v1.2.3\n")
    catalog = root / ".kuzushi/catalogs/owned.toml"
    catalog.parent.mkdir(parents=True, exist_ok=True)
    catalog.write_text('schema_version = "1"\n[[entry]]\nid = "owned-note"\ntitle = "Owned catalog note"\ncwe = "CWE-20"\nseverity = "low"\nhunt = "owned-inert"\n')
    save(evidence, "source-before", source_identity(root))
    all_tools = native(root, evidence, "catalog-all", ["tools", "--all", "--json"])
    defaults = native(root, evidence, "catalog-default", ["tools", "--json"])
    indexed = {row["name"]: row for row in all_tools}
    assert indexed["threat-intel:discover"]["maturity"] == "labs"
    assert "threat-intel:discover" not in {row["name"] for row in defaults}
    for name in ["threat-intel:discover", "threat-intel:list"]:
        assert indexed[name]["phase_result"] is False


def verify(root, evidence, stage):
    assert source_identity(root) == json.loads((evidence / "source-before.json").read_text())
    runs = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/runs").glob("*/result.json")]
    candidates = [row for row in runs if "packageCount" in row.get("data", {})]
    assert len(candidates) == 1, candidates
    result = candidates[0]
    assert result["status"] == "partial" and result["data"]["packageCount"] == 1
    assert result["data"]["coverage"]["complete"] is False
    stored = json.loads((root / ".kuzushi/threat-intel/candidates.json").read_text())
    assert stored["coverage"] == result["data"]["coverage"]
    assert "Coverage is incomplete" in result["summary"]
    assert "sbom-scan:scan" in result["summary"]
    candidate_path = next(path for path in (root / ".kuzushi/v3/runs").glob("*/result.json")
                          if json.loads(path.read_text()) == result)
    (evidence / "replay-command.txt").write_text("replay " + candidate_path.parent.name)
    for base in [root / ".kuzushi", root / ".kuzushi/v3"]:
        for path in (base / "workflow").glob("phase-attempts*.jsonl"):
            assert not path.read_text().strip(), path
    db_path = root / ".kuzushi/v3/index.sqlite3"
    with sqlite3.connect(db_path.as_uri() + "?mode=rw", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
            if name in tables:
                assert db.execute("SELECT count(*) FROM " + name).fetchone()[0] == 0, name
    if stage == "restarted":
        assert any(row.get("data", {}).get("summary", {}).get("totalEntries") == 1 for row in runs)
        assert any(row.get("data", {}).get("componentCount") == 2 for row in runs)
    save(evidence, stage + "-check", {"partialCandidateRuns": 1, "providerRequests": 0,
        "sourceUnchanged": True, "sourceExecuted": False, "phaseAttempts": 0, "findings": 0})


def inspect_pages(evidence):
    captures = sorted(evidence.glob("*-candidates*40x12.txt"))
    text = "".join("".join(path.read_text().split()) for path in captures)
    for phrase in ["Outcome · partial", "Coverage is incomplete", "Nested manifests may be omitted", "sbom-scan:scan"]:
        assert "".join(phrase.split()) in text, phrase
    assert len({path.read_text() for path in captures}) > 2
    save(evidence, "narrow-pages-check", {"coverageWarningReadable": True, "captures": len(captures)})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    evidence.mkdir(parents=True, exist_ok=True)
    if sys.argv[3] == "seed":
        seed(root, evidence)
    elif sys.argv[3] == "pages":
        inspect_pages(evidence)
    else:
        verify(root, evidence, sys.argv[3])
