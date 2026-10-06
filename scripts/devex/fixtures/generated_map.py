"""Real recorded context generation with a mocked provider and labeled queue fixture."""
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path


def seed(root, evidence):
    assert (root / ".git").is_dir(), "Use only the harness repository"
    evidence.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text('print("hello")\n')
    (root / "config.env").write_text("# Offline greeting fixture, no credentials.\n")
    repo = Path(__file__).resolve().parents[3]
    env = dict(os.environ, KUZUSHI_TEST_CONTEXT_MAP_TARGET=str(root))
    env.pop("OPENAI_API_KEY", None)
    env.pop("ANTHROPIC_API_KEY", None)
    command = ["cargo", "test", "-p", "kuzushi-core", "--lib",
               "capabilities::campaign::context_study::tests::map_handoff::export_generated_map_tui_fixture",
               "--", "--exact", "--ignored", "--nocapture"]
    with (evidence / "offline-generator.log").open("w") as output:
        result = subprocess.run(command, cwd=repo, env=env, stdout=output,
                                stderr=subprocess.STDOUT, timeout=180, check=False)
    assert result.returncode == 0, "Inspect offline-generator.log for fixture failure"
    fixture = json.loads((root / ".kuzushi/v3/context-map-fixture.json").read_text())
    (evidence / "resume-command.txt").write_text("campaign " + fixture["campaignId"])
    verify(root, evidence, "seeded")


def verify(root, evidence, stage):
    state = root / ".kuzushi/v3"
    fixture = json.loads((state / "context-map-fixture.json").read_text())
    assert fixture["mockProviderCalls"] == 1 and fixture["liveProviderCalls"] == 0
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    assert manifest["active"] == fixture["active"] != fixture["generated"]
    result = json.loads((state / "runs/context-result/result.json").read_text())
    assert result["data"]["modelRef"] == fixture["generated"]
    assert result["status"] == "completed", "Only complete generated results can enter Map"
    artifacts = [item["path"] for item in result["artifacts"]
                 if item["label"] in ("normalized threat model", "harness-schema threat model (markdown)",
                                      "immutable threat model")]
    assert len(artifacts) == 3, "Generation must record all three declared build artifacts"
    assert any("threat-models/objects/" in path for path in artifacts)
    assert all((root / path).is_file() for path in artifacts)
    assert result["data"]["document"]["title"] == "Offline generated context"
    queue = json.loads((state / "campaigns" / fixture["campaignId"] / "queue.json").read_text())
    assert len(queue["jobs"]) == 1 and queue["jobs"]["context-001"]["state"] == "completed"
    events_path = state / "workflow/phase-attempts.jsonl"
    events = [json.loads(line) for line in events_path.read_text().splitlines()] if events_path.exists() else []
    maps = [event for event in events if event.get("event") == "phase_attempt_completed"]
    decisions = [event for event in events if event.get("event") == "phase_attempt_disposition_recorded"]
    expected_maps = 0 if stage == "seeded" else 1
    assert len(maps) == expected_maps, "Map handoff cannot create duplicate attempts"
    if maps:
        assert maps[0]["phase"] == "map" and maps[0]["runRefs"] == ["context-result"]
    if stage in ("accepted", "resumed", "drifted", "refused"):
        assert len(decisions) == 1 and decisions[0]["disposition"]["kind"] == "selected"
    else:
        assert not decisions, "Review is separate from acceptance"
    with sqlite3.connect((state / "index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        assert connection.execute("select count(*) from investigation_call_reservations").fetchone()[0] == 1
        assert connection.execute("select count(*) from investigation_work_attempts").fetchone()[0] == 1
    if stage == "resumed":
        ansi = next(evidence.glob("*-resumed-map.ansi")).read_text()
        for sgr in re.findall(r"\x1b\[([\d;]*)m", ansi):
            assert not any(30 <= int(code) <= 38 or 40 <= int(code) <= 48 or 90 <= int(code) <= 107
                           for code in sgr.split(";") if code)
    (evidence / (stage + "-receipt.json")).write_text(json.dumps({
        **fixture, "stage": stage, "mapAttempts": len(maps), "operatorDecisions": len(decisions),
        "discoveryJobsStarted": 0, "queueCompletionInjected": True,
    }, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, action = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if action == "seed":
        seed(root, evidence)
    elif action == "drift":
        (root / "later.rs").write_text("pub fn later() {}\n")
        verify(root, evidence, "drifted")
    else:
        verify(root, evidence, action)
