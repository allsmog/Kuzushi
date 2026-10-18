"""Paged literal membership and context display over an owned inert repository."""
import hashlib
import json
import sys
from pathlib import Path

import literal_scope_membership as literal
from installed_scope_study import current_counts, native, save


def source_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*.py")) if ".kuzushi" not in path.parts}


def seed(root, evidence, home):
    literal.seed(root, evidence, home)
    for index in range(128):
        (root / "app" / ("member%03d.py" % index)).write_text("# Owned inert nonmatching source.\n")
    save(evidence, "tree-source-before", source_hashes(root))


def verify_boundaries(root, evidence, stage):
    value = literal.review(root, evidence)
    draft, coverage = value["record"]["draft"], value["coverage"]
    assert coverage["enumeratedFiles"] == 131 and coverage["enumerationComplete"]
    assert coverage["uncoveredFiles"]["total"] == coverage["overlaps"]["total"] == 0
    if stage == "whole":
        assert len(draft["scopes"]) == 1 and draft["scopes"][0]["paths"] == ["."]
        assert not draft["exclusions"]
    else:
        assert {s["name"]: s["paths"] for s in draft["scopes"]} == {"Spaced app": [" app "], "Other source": ["app", "loose.py"]}
        for scope in draft["scopes"]:
            members = coverage["discoveryMembers"].get(scope["id"], {"total": 0, "files": []})
            expected = (0 if stage == "excluded" else 1) if scope["name"] == "Spaced app" else 130
            assert members["total"] == expected
        if stage == "excluded":
            assert draft["exclusions"][0]["path"] == " app /lib.py"
            assert coverage["excludedFiles"]["files"] == [" app /lib.py"]
        else:
            assert not draft["exclusions"] and coverage["excludedFiles"]["total"] == 0
    if stage == "invalid":
        assert value["reference"] == json.loads((evidence / "scope-restored.json").read_text())["reference"]
    if stage == "paged":
        scope = next(s for s in draft["scopes"] if s["name"] == "Other source")
        page = native(root, evidence, "tree-last-page", ["run", "pack:scopes", "--input", json.dumps({
            "operation": "files", "proposalRef": value["reference"], "fileFilter": {"kind": "scope", "scopeId": scope["id"]}, "offset": 128, "pageSize": 32})])["data"]
        assert page == {"offset": 128, "total": 130, "files": ["app/member127.py", "loose.py"]}
    assert bool(value["record"]["acceptance"]) == (stage == "accepted")
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    assert all(count in [None, 0] for count in current_counts(root, evidence).values())
    save(evidence, "scope-" + stage, value)


def verify(root, evidence, stage):
    assert source_hashes(root) == json.loads((evidence / "tree-source-before.json").read_text())
    assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text()).get("active") is None
    if stage in ["split", "excluded", "restored", "invalid", "whole", "accepted", "paged"]:
        verify_boundaries(root, evidence, stage)
        return
    literal.verify_work(root, evidence, "restart" if stage == "associations" else stage)
    plan, cases = literal.plan(root, evidence)
    for case in cases.values():
        context = case["baseInput"]["threatModelRef"]
        assert (context is None) == (case["label"] == "Spaced app")
    if stage == "associations":
        save(evidence, "associations-check", {"campaignId": plan["campaignId"], "exactScopeReference": True,
            "spaced": "explicitly omitted", "other": "inherits frozen common", "sourceExecuted": False, "providerCalls": 0})


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]))
    else:
        verify(root, evidence, stage)
