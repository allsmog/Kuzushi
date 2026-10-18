"""Native frozen scanner text, missing-object refusal and restart. No model work."""
import hashlib
import json
import os
import sys
from pathlib import Path
from context_comparison import run_tool
from scanner_field_preview import check_empty_store
from study_context import seed


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def plans(root):
    return [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]


def object_path(root, reference):
    digest = reference["object"]["hash"].removeprefix("sha256:")
    matches = list((root / ".kuzushi").rglob(digest))
    assert len(matches) == 1, "Expected one exact saved context object"
    return matches[0]


def verify(root, evidence, stage):
    refs = json.loads((evidence / "context-refs.json").read_text())
    drafts = plans(root)
    assert len(drafts) == 1
    plan = drafts[0]
    assert plan["baseInput"]["threatModelRef"] == refs["selected"]
    frozen = plan["baseInput"]["threatModelDigestRef"]
    assert len(plan["jobs"]) == 3 and plan["workers"] == 1
    assert all(job["input"]["threatModelDigestRef"] == frozen for job in plan["jobs"])
    data = run_tool(os.environ["KUZUSHI_NATIVE_BIN"], root, evidence, stage + "-read", "threat-model:read",
                    {"threatModelRef": refs["selected"], "threatModelDigestRef": frozen})["data"]
    preview = data["scannerContextPreview"]
    assert preview["frozenReference"] == frozen
    matches = stage != "drifted"
    assert preview["origin"] == "frozen-study" and preview["sourceMatchesAtInspection"] is matches
    assert preview["sha256"] == "sha256:" + hashlib.sha256(preview["text"].encode()).hexdigest()
    assert "alpha" in preview["text"] and "beta" not in preview["text"]
    if stage == "prepared":
        save(evidence, "expected-projection", preview)
        (evidence / "resume-command.txt").write_text("campaign " + plan["campaignId"])
    else:
        expected = json.loads((evidence / "expected-projection.json").read_text())
        expected["sourceMatchesAtInspection"] = matches
        assert preview == expected
    assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())["active"] == refs["active"]
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/queue.json"))
    check_empty_store(root)
    save(evidence, stage + "-check", {"providerRequests": 0, "jobsStarted": 0, "plans": 1,
        "fixedJobs": 3, "activeContextUnchanged": True, "sourceExecuted": False,
        "receiptReferenceMatchesPlan": True,
        "sourceMatchesAtInspection": matches,
        "savedTextHash": preview["sha256"], "operatorVisualApproval": False})


def main():
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence)
        return
    if stage == "drift":
        assert root.name == "fixture-target" and root.parent == evidence
        path = root / "context-source-change.txt"
        assert not path.exists()
        path.write_text("Owned inert source change. Never executed.\n")
        return
    if stage in ["hide", "restore"]:
        reference = plans(root)[0]["baseInput"]["threatModelDigestRef"]
        backup = evidence / "saved-context-backup.json"
        location = evidence / "saved-context-location.txt"
        if stage == "hide":
            path = object_path(root, reference)
            backup.write_bytes(path.read_bytes())
            location.write_text(str(path))
            path.unlink()
        else:
            Path(location.read_text()).write_bytes(backup.read_bytes())
        check_empty_store(root)
        return
    verify(root, evidence, stage)


if __name__ == "__main__":
    main()
