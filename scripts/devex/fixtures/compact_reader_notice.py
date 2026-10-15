"""Observe only the owned native receipt pane. No model or source execution."""
import json
import subprocess
import sys
from pathlib import Path

DRAFT = "retained-note-42"


def owned_pane(root):
    output = subprocess.check_output(["tmux", "list-panes", "-a", "-F",
        "#{pane_id}\t#{pane_current_path}\t#{alternate_on}"], text=True)
    panes = [parts[0] for line in output.splitlines()
             if len(parts := line.split("\t")) == 3 and parts[2] == "1"
             and Path(parts[1]).resolve() == root]
    assert len(panes) == 1, "Expected one owned live native pane"
    return panes[0]


def observe(root, evidence, stage):
    pane = owned_pane(root)
    screen = subprocess.check_output(["tmux", "capture-pane", "-p", "-t", pane], text=True)
    cursor = subprocess.check_output(["tmux", "display-message", "-p", "-t", pane,
        "#{cursor_x}:#{cursor_y}"], text=True).strip()
    cursor_visible = subprocess.check_output(["tmux", "display-message", "-p", "-t", pane,
        "#{cursor_flag}"], text=True).strip()
    if stage in ["failed", "partial"]:
        assert "Outcome · " + stage in screen
        assert "Esc dismiss" in screen and "logs" in screen
        assert "ERROR" in screen if stage == "failed" else "NOTICE" in screen
    elif stage == "insertion":
        assert "retained-noteX-42" in screen, screen
    else:
        assert DRAFT in screen, screen
        if stage == "after-route":
            assert "LOGS" in screen
    (evidence / (stage + "-check.json")).write_text(json.dumps({
        "pane": pane, "terminalCursor": cursor, "terminalCursorVisible": cursor_visible,
        "draftVisible": DRAFT in screen,
        "outcomeVisible": "Outcome · " in screen, "stage": stage}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    observe(root, evidence, sys.argv[3])
