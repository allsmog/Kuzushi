"""Check imported assertion reading without changing evidence or starting work."""
import json
import re
import sys
from pathlib import Path

from dfd_literal_links import verify
from evidence_origin_exports import export, verify_exports


def inspect(root, evidence, stage):
    if stage == "navigation":
        verify(root, evidence, stage)
    else:
        verify_exports(root, evidence)
    captures = sorted(evidence.glob("[0-9][0-9]-*.txt"))
    assert captures
    assert all("model-generated reasoning" not in path.read_text() for path in captures)
    narrow = [path for path in captures if "-narrow-" in path.name]
    assert narrow
    for path in narrow:
        provenance = json.loads(path.with_suffix(".provenance.json").read_text())
        assert provenance["actual_dimensions"] == {"width": 40, "height": 12}
    pages = "\n".join(path.read_text() for path in narrow)
    assert "reasoning assertion" in pages, "Narrow reading did not reach assertion origin"
    assert "observed code evidence" in pages, "Narrow reading did not reach grounded source origin"
    if stage == "restarted":
        assert "reasoning assertion" in next(evidence.glob("*-restarted-literal.txt")).read_text()
        ansi = next(evidence.glob("*-restarted-literal.ansi")).read_text()
        for sgr in re.findall(r"\x1b\[([\d;]*)m", ansi):
            assert not any(30 <= int(code) <= 38 or 40 <= int(code) <= 48
                           or 90 <= int(code) <= 107 for code in sgr.split(";") if code)
    (evidence / (stage + "-origin-check.json")).write_text(json.dumps({
        "assertionOrigin": "reasoning assertion", "inventedModelOrigin": False,
        "narrowPages": len(narrow), "observedCodeLabelReached": True,
        "providerRequests": 0, "sourceExecuted": False, "findingAndDecisionStateUnchanged": True,
    }, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = sys.argv[1:4]
    root, evidence = Path(root).resolve(), Path(evidence).resolve()
    if stage == "export":
        assert len(sys.argv) == 5
        export(root, evidence, Path(sys.argv[4]).resolve())
    else:
        assert stage in ["navigation", "restarted"] and len(sys.argv) == 4
        inspect(root, evidence, stage)
