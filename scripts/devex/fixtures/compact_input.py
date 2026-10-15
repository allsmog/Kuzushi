"""Inspect native compact controls and terminal input over owned inert sources."""
import json
import sys
from pathlib import Path

from completion_input import counts, save, seed, sources, verify


def snapshot(evidence, label):
    paths = list(evidence.glob("*-" + label + ".txt"))
    assert len(paths) == 1, paths
    return paths[0], paths[0].read_text()


def inspect(evidence, label):
    path, text = snapshot(evidence, label)
    if label == "compact-controls":
        for control in ["Ctrl+Y", "inspect", "Esc", "clear", "Ctrl+_", "undo", "Ctrl+C"]:
            assert control in text, (control, text)
    elif label == "single-paging":
        assert text.count("PgUp/PgDn") == 1, text
    elif label == "typed-quit":
        assert "› quit" in text.splitlines()[-1], text
    elif label == "coalesced-escape-end":
        save(evidence, "escape-end-observation", {
            "capture": path.name, "promptLine": text.splitlines()[-1],
            "endSequenceFragmentVisible": "[4~" in text.splitlines()[-1],
            "terminalParserQualified": False})
        return
    save(evidence, label + "-verified", {"capture": path.name})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "state":
        verify(root, evidence, "restarted")
        assert sources(root) == json.loads((evidence / "source-before.json").read_text())
        save(evidence, "final-state", {"sourceUnchanged": True, "counts": counts(root, evidence)})
    else:
        inspect(evidence, stage)
