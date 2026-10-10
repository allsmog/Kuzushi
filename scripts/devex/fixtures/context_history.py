"""Owned exact-history receipts. No model, scanner or target-source execution."""
import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path


def saved(root, evidence):
    before = json.loads((evidence / "before.json").read_text())
    current = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert hashlib.sha256((root / "reader.py").read_bytes()).hexdigest() == before["sourceSha256"]
    for key, ref in before["refs"].items():
        path = object_path(root, ref)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == before["objects"][key]
    with sqlite3.connect((root / ".kuzushi/v3/index.sqlite3").as_uri()+"?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["finding_observations", "investigation_work_attempts", "investigation_call_reservations"]:
            if table in tables:
                assert db.execute("select count(*) from "+table).fetchone()[0] == 0
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    return before, current


def object_path(root, reference):
    return root / ".kuzushi/threat-models/objects" / ("sha256-"+reference["sha256"].removeprefix("sha256:")+".json")


def receipts(root, evidence):
    seed_ids = set(json.loads((evidence / "seed-run-ids.json").read_text()))
    return [json.loads(path.read_text()) for path in sorted((root / ".kuzushi/v3/runs").glob("*/result.json")) if path.parent.name not in seed_ids]


def verify(root, evidence, stage):
    before, current = saved(root, evidence)
    refs = before["refs"]
    if stage in ["compared", "inspected", "retried"]:
        assert current["active"] == refs["beta"]
        assert hashlib.sha256((root / ".kuzushi/threat-models/manifest.json").read_bytes()).hexdigest() == before["manifestSha256"]
    if stage == "compared":
        matches = [r for r in receipts(root, evidence) if r.get("data", {}).get("from", {}).get("revisionId") == refs["alpha"]["revisionId"] and r.get("data", {}).get("to", {}).get("revisionId") == refs["copy"]["revisionId"]]
        assert len(matches) >= 1 and len(matches[-1]["data"]["contextText"]) == 3
        assert matches[-1]["data"]["target"] == str(root)
    elif stage in ["inspected", "retried"]:
        matches = [r for r in receipts(root, evidence) if r.get("data", {}).get("modelRef") == refs["copy"] and r.get("data", {}).get("document", {}).get("systemContext") == "Reviewed overview α\nSecond line"]
        assert len(matches) >= (2 if stage == "retried" else 1)
    elif stage == "activated":
        assert current["active"] == refs["alpha"]
    elif stage in ["restored", "recovered"]:
        assert current["active"]["modelId"] == refs["alpha"]["modelId"]
        assert current["active"]["revisionId"] != refs["alpha"]["revisionId"]
        model = next(m for m in current["models"] if m["modelId"] == refs["alpha"]["modelId"])
        assert model["revisions"][-1]["source"] == "restore"
    (evidence / (stage+"-history-check.json")).write_text(json.dumps({"stage":stage,"active":current["active"],"sourceUnchanged":True,"originalObjectsUnchanged":True,"providerReservations":0,"findingObservations":0,"campaignPlans":0}, indent=2)+"\n")


def main():
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        subprocess.run([sys.executable, "-B", str(Path(__file__).with_name("context_lifecycle.py")), str(root), str(evidence), "seed"], check=True, timeout=180)
        (evidence / "operator-draft.txt").write_text("preserved draft α")
        ids = [path.parent.name for path in (root / ".kuzushi/v3/runs").glob("*/result.json")]
        (evidence / "seed-run-ids.json").write_text(json.dumps(ids)+"\n")
    elif stage in ["hide-copy", "return-copy"]:
        refs = json.loads((evidence / "before.json").read_text())["refs"]
        source, backup = object_path(root, refs["copy"]), evidence / "retained-copy-object.json"
        if stage == "hide-copy": source.rename(backup)
        else: backup.rename(source)
    else:
        verify(root, evidence, stage)


if __name__ == "__main__": main()
