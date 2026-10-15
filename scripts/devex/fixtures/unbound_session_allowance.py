"""A direct session question must not spend the exhausted owned allowance."""
import json
import sys
from pathlib import Path

from live_investigation import FIXTURE
from preserved_live_review import inspect_completed, save, verify

QUESTION = "Explain the owned greeting context without executing source."


def seed(root, evidence):
    inspect_completed(root, evidence)
    runs = root / ".kuzushi/v3/runs"
    save(evidence, "agent-runs-before", sorted(path.name for path in runs.glob("agent-*") if path.is_dir()))
    (evidence / "question-command.txt").write_text("ask " + QUESTION)


def check(root, evidence, stage):
    verify(root, evidence, stage)
    before = set(json.loads((evidence / "agent-runs-before.json").read_text()))
    runs = [path for path in (root / ".kuzushi/v3/runs").glob("agent-*") if path.is_dir() and path.name not in before]
    assert len(runs) == 1, "Observation cannot restart or submit another question"
    run = runs[0]
    assert json.loads((run / "input.json").read_text())["question"] == QUESTION
    meta = json.loads((run / "run.json").read_text())
    result = json.loads((run / "result.json").read_text())
    assert result["status"] == "blocked", result
    assert not meta.get("llmCalls"), "Unbound Ask cannot start a model request"
    save(evidence, stage + "-blocked-session", {"runId":run.name,"status":"blocked",
        "modelRequests":0,"investigationRequests":6,"humanDecisionPreserved":True,
        "sourceExecuted":False,"allowanceRevised":False,"question":QUESTION})


if __name__ == "__main__":
    root,evidence,stage = Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
    assert root == FIXTURE / "target"
    evidence.mkdir(parents=True,exist_ok=True)
    if stage == "seed": seed(root,evidence)
    else: check(root,evidence,stage)
