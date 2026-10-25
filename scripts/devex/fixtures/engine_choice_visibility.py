"""Check actual captured list rails and retain zero-work fixture receipts."""
import sys
import re
from pathlib import Path

from engine_readiness import verify


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    verify(root, evidence, stage)
    if stage == "tall":
        snapshots = list(evidence.glob("*-complete-tall-list.txt"))
        assert len(snapshots) == 1, snapshots
        lines = snapshots[0].read_text().splitlines()
        visible = [line for line in lines if re.match(r"^\s*│\s*(?:▸\s*)?\[(?:x| )\] ", line)]
        assert len(visible) == 14, visible
        (evidence / "tall-visible-rows.txt").write_text("\n".join(visible) + "\n")
    if stage in ["top", "middle", "bottom", "restarted-bottom"]:
        snapshots = list(evidence.glob("*-" + stage + "-40x12.txt"))
        assert len(snapshots) == 1, snapshots
        lines = snapshots[0].read_text().splitlines()
        assert len(lines) == 12
        rail = "".join(line[37] for line in lines[3:6])
        expected = {"top": (" ", "↓"), "middle": ("↑", "↓"),
                    "bottom": ("↑", " "), "restarted-bottom": ("↑", " ")}
        assert (rail[0], rail[-1]) == expected[stage], (stage, rail)
        (evidence / (stage + "-rail.txt")).write_text(rail + "\n")
