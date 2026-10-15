"""Real default Map work and manifest inspection with unsent operator drafts."""
import hashlib
import json
import sys
import time
from pathlib import Path

from secret_settings import ledger


def save(evidence, name, value):
    (evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def sources(root):
    files = [root / "package.json", *sorted((root / "notes").glob("*.md"))]
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}


def seed(root, evidence, home):
    assert not (evidence / "source-before.json").exists(), "Fixture already initialized"
    assert home == (evidence / "home").resolve()
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "package.json").write_text('{"name":"owned-input-fixture","license":"MIT","dependencies":{"owned-example":"*"}}\n')
    notes = root / "notes"
    notes.mkdir(exist_ok=True)
    for index in range(64):
        header = "# Owned inert reading fixture " + str(index) + "\n"
        text = "Source-only text used to observe keyboard ownership during bounded inventory work.\n"
        (notes / (str(index) + ".md")).write_text(header + text * 1600)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    (evidence / "multiline.txt").write_text("first owned α\nsecond owned β\n")
    (evidence / "scan-command.txt").write_text('run sast:scan ' + json.dumps({
        "taskMode":"manual", "tasks":["dep-hygiene"], "triage":False,
        "verify":False, "autoPatch":False, "threatModelRef":None}))
    (evidence / "scan-draft.txt").write_text("operator α ")
    save(evidence, "source-before", sources(root))


def events(root):
    path = root / ".kuzushi/v3/workflow/phase-attempts.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def completed_map(root):
    return [row for row in events(root) if row["event"] == "phase_attempt_completed"
        and row["phase"] == "map" and row["outcome"] == "completed"]


def counts(root, evidence):
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        names = ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]
        return {name:db.execute("select count(*) from " + name).fetchone()[0] if name in tables else None for name in names}


def scan_results(root):
    rows = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/runs").glob("*/result.json")]
    return [row for row in rows if row.get("data", {}).get("findingsCount") == 1]


def verify(root, evidence, stage):
    scanned = stage in ["scan-draft", "restarted"]
    draft_stage = stage in ["map-draft", "map-edited", "map-restored"]
    for _ in range(40):
        maps = completed_map(root)
        dispositions = [row for row in events(root) if row["event"] == "phase_attempt_disposition_recorded"]
        scans = scan_results(root) if scanned else []
        selected = draft_stage or len(dispositions) == 1
        if maps and selected and (not scanned or scans):
            break
        time.sleep(1)
    assert maps, "Actual default Map did not complete"
    assert sources(root) == json.loads((evidence / "source-before.json").read_text())
    if draft_stage:
        assert not dispositions, "Unsent keys selected or discarded a phase result"
    else:
        assert len(dispositions) == 1 and dispositions[0]["disposition"]["kind"] == "selected"
        assert dispositions[0]["attemptId"] == maps[-1]["attemptId"]
    recorded = counts(root, evidence)
    assert recorded["investigation_call_reservations"] in [0, None]
    assert recorded["investigation_work_attempts"] in [0, None]
    assert recorded["review_decisions"] in [0, None]
    assert recorded["finding_observations"] == (1 if scanned else 0), recorded
    if stage == "prereq-draft":
        assert not scan_results(root), "Held draft started a scan over the prerequisite question"
    if scanned:
        assert len(scans) == 1 and scans[0]["status"] == "completed"
        assert scans[0]["data"]["engines"] == ["dep-hygiene"]
    save(evidence, stage + "-verified", {"actualMapCompleted":True, "sourceUnchanged":True,
        "targetSourceExecuted":False, "providerRequests":0, "counts":recorded,
        "scriptedMapSelections":len(dispositions)})


def draft(evidence, label, suffix):
    paths = list(evidence.glob("*-" + label + ".txt"))
    assert len(paths) == 1, paths
    last = paths[0].read_text().splitlines()[-1].rstrip()
    assert last.endswith(suffix), (label, last, suffix)
    save(evidence, label + "-draft-verified", {"draftSuffix":suffix, "source":paths[0].name})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    elif stage == "draft":
        draft(evidence, *sys.argv[4:6])
    else:
        verify(root, evidence, stage)
