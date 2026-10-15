"""Owned synthetic context cuts. No inference, findings or source execution."""
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from context_comparison import run_tool
from context_diagram import document


def save(output, name, value):
    (output / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def native(root, output, name, tool, value, binary=None):
    return run_tool(binary or os.environ["KUZUSHI_NATIVE_BIN"], root, output,
                    name, tool, value)["data"]


def prepare(root, output):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "reader.py").write_text("# Owned inert rendering fixture. Never executed.\n")
    active = native(root, output, "active-import", "threat-model:import",
                    {"document": document("Active"), "label": "Active context", "activate": True})
    selected = document("Included context")
    selected["systemContext"] = "Synthetic historical context solely to inspect rendering. No security verdict."
    selected["dfd"]["nodes"][1]["description"] = "界" * 200 + "OMITTED_FIELD_TAIL"
    patterns = [{"title": f"Owned historical pattern {index}", "location": "reader.py:1",
                 "code": "界" * 200 + "OMITTED_CODE_TAIL"} for index in range(13)]
    selected["threats"] = [{"id": f"owned-guidance-{index}", "title": "Synthetic historical guidance", "severity": "low",
        "targetElementIds": ["api"], "variantPatterns": group} for index, group in enumerate([patterns[:8], patterns[8:]])]
    imported = native(root, output, "selected-import", "threat-model:import",
                      {"document": selected, "label": "Context with explicit cuts", "activate": False})
    reference = imported["modelRef"]
    baseline = native(root, output, "previous-renderer", "threat-model:read",
                      {"threatModelRef": reference}, os.environ["KUZUSHI_SCANNER_BASELINE_BIN"])
    save(output, "expected", {"reference": reference, "activeReference": active["modelRef"],
         "sourceSha256": hashlib.sha256((root / "reader.py").read_bytes()).hexdigest(),
         "previousDigest": baseline["scannerContextPreview"]["text"],
         "previousDigestHash": baseline["scannerContextPreview"]["sha256"]})
    inspect(root, output, "prepared")


def inspect(root, output, stage):
    expected = json.loads((output / "expected.json").read_text())
    data = native(root, output, "read-" + stage, "threat-model:read",
                  {"threatModelRef": expected["reference"]})
    preview = data["scannerContextPreview"]
    assert preview["text"] == expected["previousDigest"]
    assert preview["sha256"] == expected["previousDigestHash"]
    assert preview["sha256"] == "sha256:" + hashlib.sha256(preview["text"].encode()).hexdigest()
    assert "Component 2 description: first 200 of 218 characters; 18 omitted." in preview["omissions"]
    assert "Variant patterns: first 12 of 13 items; 1 omitted." in preview["omissions"]
    fields = ", ".join(str(index) for index in range(1, 13))
    assert f"Variant pattern code fields {fields} (each): first 200 of 217 characters; 17 omitted." in preview["omissions"]
    assert "OMITTED_FIELD_TAIL" not in preview["text"]
    assert "OMITTED_CODE_TAIL" not in preview["text"]
    assert "Owned historical pattern 12" not in preview["text"]
    assert data["document"]["dfd"]["nodes"][1]["description"].endswith("OMITTED_FIELD_TAIL")
    patterns = [pattern for threat in data["document"]["threats"] for pattern in threat["variantPatterns"]]
    assert len(patterns) == 13 and patterns[0]["code"].endswith("OMITTED_CODE_TAIL")
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == expected["activeReference"]
    assert hashlib.sha256((root / "reader.py").read_bytes()).hexdigest() == expected["sourceSha256"]
    check_empty_store(root)
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    save(output, stage + "-check", {"sourceUnchanged": True, "sourceExecuted": False,
         "providerRequests": 0, "findings": 0, "campaignPlans": 0,
         "activeContextUnchanged": True, "documentTailsRetained": True,
         "digestUnchangedFromPreviousRuntime": True, "digestHash": preview["sha256"],
         "operatorVisualApproval": False})


def check_empty_store(root):
    path = root / ".kuzushi/v3/index.sqlite3"
    if not path.exists():
        return
    with sqlite3.connect(path.as_uri() + "?mode=rw", uri=True) as db:
        db.execute("pragma query_only=on")
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]:
            assert table not in tables or db.execute("select count(*) from " + table).fetchone()[0] == 0


if __name__ == "__main__":
    root, output, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "prepare":
        prepare(root, output)
    else:
        inspect(root, output, stage)
