"""Read the completed owned replay study without granting any new work."""
import hashlib
import json
import sys
from pathlib import Path

from secret_settings import ledger

REPO = Path(__file__).resolve().parents[3]
ROOT = REPO / "scripts/devex/artifacts/scope-replay-native-current-20261027/J399-attempt-3/native/20261027-150833/J399/fixture-target"


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def durable_state(evidence):
    state = ROOT / ".kuzushi/v3"
    paths = list((state / "scan-scopes").rglob("*.json"))
    paths += list((ROOT / ".kuzushi/threat-models").rglob("*.json"))
    paths += list((state / "campaigns").glob("*/plan.json"))
    paths += list((state / "campaigns").glob("*/queue.json"))
    paths += list((state / "runs").glob("*/phase-stages.jsonl"))
    paths += [ROOT / ".kuzushi/reports/findings.json"]
    source = read(ROOT.parent / "source-before.json")
    assert len(source) == 602
    assert all(digest(ROOT / name) == value for name, value in source.items())
    with ledger(ROOT, evidence) as db:
        counts = {name: db.execute("SELECT count(*) FROM " + name).fetchone()[0] for name in
                  ["finding_observations", "finding_identities", "review_decisions", "investigation_work_attempts",
                   "investigation_call_reservations", "investigation_allowance_revisions"]}
        assert list(counts.values()) == [24, 8, 8, 22, 1, 2]
    return {"hashes": {str(path): digest(path) for path in paths}, "counts": counts}


def inspect(evidence, stage, home=None):
    if stage == "seed":
        config = home / ".kuzushi/v3/config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text('model = "openai-codex:gpt-6-luna"\n[runtime]\nthinking_level = "low"\n')
        (evidence / "before.json").write_text(json.dumps(durable_state(evidence), indent=2) + "\n")
        return
    assert durable_state(evidence) == read(evidence / "before.json")
    assert not (evidence / "denied-fetch.jsonl").exists()
    if stage == "paged":
        text = "".join(path.read_text() for path in sorted(evidence.glob("*-compact-page-*.txt")))
        normalized = "".join(text.split())
        for phrase in ["Investigation cost: cost not recorded", "2 protected review remaining", "no complete repository coverage claim"]:
            assert "".join(phrase.split()) in normalized, phrase
    result = {"stage": stage, "durableStateUnchanged": True, "sourceFilesUnchanged": 602,
              "liveProviderRequests": 0, "credentialsCopied": False, "newJobs": 0, "newDecisions": 0}
    (evidence / (stage + "-check.json")).write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    inspect(Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else None)
