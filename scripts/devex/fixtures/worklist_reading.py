"""Check complete keyboard reading of an owned worklist at 40 by 12."""
import json
import sys
from pathlib import Path
from gallery_capture import window


def compact(text):
    return "".join(text.split())


def inspect(root, evidence, prefix, deep):
    captures = sorted(evidence.glob("*-" + prefix + "-*.txt"))
    assert len(captures) == 17, len(captures)
    display = {}
    totals = set()
    logical_totals = set()
    for capture in captures:
        shown = window(capture, "RISK WORKLIST")
        assert shown["first"] is not None, capture
        logical_totals.add(shown["logicalTotal"])
        for number, text in enumerate(shown["body"], shown["first"]):
            assert number not in display or display[number] == text, (capture, number)
            display[number] = text
        totals.add(shown["total"])
    assert len(totals) == len(logical_totals) == 1, (totals, logical_totals)
    total = totals.pop()
    assert set(display) == set(range(1, total + 1)), sorted(set(range(1, total + 1)) - set(display))
    text = compact("".join(display[line] for line in range(1, total + 1)))
    state = root / ".kuzushi/v3"
    current = (state / "latest").read_text().strip()
    result = json.loads((state / "runs" / current / "result.json").read_text())
    for row in result["data"]["rows"]:
        assert compact(row["path"]) in text, (row["path"], text)
    if deep:
        for phrase in ["Bounds: 2000 file attempts", "16.0 KiB per file", "16.0 MiB source total",
            "512.0 MiB", "complete repository coverage is not established", "prefix limits: 1",
            "files with evidence limits: 1"]:
            assert compact(phrase) in text, (phrase, text)
    assert "notrequested" in text
    assert "notsupported" in text
    assert "PhaseA" not in text and "PhaseB" not in text
    (evidence / (prefix + "-reading.json")).write_text(json.dumps({
        "captures": len(captures), "logicalRows": logical_totals.pop(), "displayLines": len(display),
        "allContinuationsReachable": True, "completePathsReachable": True,
        "everyCaptureStayedInWorklist": True, "liveProviderRequests": 0,
        "humanAccepted": False}, indent=2) + "\n")


if __name__ == "__main__":
    inspect(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4] == "deep")
