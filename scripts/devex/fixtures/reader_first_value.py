"""Owned source-only reader checks. Existing dispatch, intercepted transport, no live calls."""
import hashlib
import json
import sys
from pathlib import Path

import systems_invariants as base
from secret_settings import save


def seed(root, evidence, home):
    base.seed(root, evidence, home)
    save(evidence, "reader-home", {"path": str(home)})


def inspect_echo(root, evidence):
    base.inspect(root, evidence, "unbound")
    command = (evidence / "unbound-command.txt").read_text()
    home = Path(json.loads((evidence / "reader-home.json").read_text())["path"])
    commands = []
    for path in (home / ".kuzushi/v3/sessions").rglob("*.jsonl"):
        for line in path.read_text().splitlines():
            row = json.loads(line)
            if row.get("type") == "command_submitted":
                commands.append(row["payload"]["command"])
    assert command in commands, "The complete submitted command must survive display folding"
    folded = next(evidence.glob("*-folded-command.txt")).read_text()
    expanded = next(evidence.glob("*-full-command.txt")).read_text()
    restored = next(evidence.glob("*-refolded-command.txt")).read_text()
    assert "command folded" in folded and "filter match" in folded
    assert "owned_omitted_context" not in "\n".join(folded.splitlines()[2:-3])
    assert "owned_omitted_context" in "\n".join(expanded.splitlines()[2:-3])
    assert "c fold commands" in expanded
    assert "command folded" in restored and "c read commands" in restored
    save(evidence, "command-disclosure", {"submittedCommandSha256": hashlib.sha256(command.encode()).hexdigest(),
        "completeCommandRetained": True, "foldedByDefault": True, "explicitReadAndReturn": True,
        "liveProviderRequests": 0, "newJobs": 0})


if __name__ == "__main__":
    root, evidence = map(Path, sys.argv[1:3])
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]))
    elif stage == "echo":
        inspect_echo(root, evidence)
    else:
        base.inspect(root, evidence, stage)
