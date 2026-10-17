"""Bounded catalog drafts on owned inert metadata. No source execution or live inference."""
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

from rejected_context import execute
from secret_settings import ledger, save

MODEL = "openai-codex:gpt-5.5"
TOOL = "taint-iris-next:catalog"
INVESTIGATION = "owned-taint-catalog"
SOURCE = "// owned_input owned_sink\n// Owned café metadata, never compiled or executed.\n"


def command(evidence, name, tool, value):
    (evidence / (name + "-command.txt")).write_text("run " + tool + " " + json.dumps(value))


def calls(evidence):
    path = evidence / "catalog-calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "owned café.c").write_text(SOURCE)
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("")
    inventory = evidence / "owned-sinks.jsonl"
    inventory.write_text('{"callee":"OwnedPrevious","cwe":"CWE-20"}\n')
    data = execute(root, home, evidence, "baseline-import", "taint-iris-next:import-sinks", {"sinksPath": str(inventory)})
    catalog = Path(data["catalogPath"])
    save(evidence, "baseline", {"path": str(catalog), "sha256": hashlib.sha256(catalog.read_bytes()).hexdigest(),
                               "sourceSha256": hashlib.sha256((root / "owned café.c").read_bytes()).hexdigest()})
    shutil.copyfile(Path(__file__).with_name("taint_catalog_provider.mjs"), evidence / "provider.mjs")
    credential = home / ".kuzushi/catalog-credentials.json"
    credential.write_text(json.dumps({"openai-codex": {"access": "offline-catalog-fixture", "expires": 99999999999999}}))
    credential.chmod(0o600)
    repo = Path(__file__).resolve().parents[3]
    bridge = ["node", "--import", str(evidence / "provider.mjs"), str(repo / "scripts/langgraph-bridge.mjs")]
    config.write_text('model="' + MODEL + '"\n[runtime]\nthinking_level="medium"\nlanggraph_bridge_command=' + json.dumps(bridge)
                     + '\n[runtime.anthropic_oauth]\ncredentials_path=' + json.dumps(str(credential)) + '\nallow_env_token=false\n')
    command(evidence, "approval", "campaign:approve-allowance", {"investigationId": INVESTIGATION,
        "expectedRevision": 0, "model": MODEL, "maxProviderCalls": 2, "protectedReviewCalls": 0,
        "reason": "Two separately invoked intercepted catalog requests, invalid then valid. No live inference, tools, source execution or follow-up jobs."})
    command(evidence, "unbound", TOOL, {"headBytes": 32})
    for name in ["invalid", "generate", "exhausted"]:
        command(evidence, name, TOOL, {"headBytes": 32, "maxFiles": 1, "maxSourceBytes": 128,
            "allowanceRef": {"schemaVersion": 1, "investigationId": INVESTIGATION, "revision": 1, "workId": "catalog-" + name}})


def results(root, tool):
    rows = []
    for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
        run = json.loads(path.read_text())
        result = path.with_name("result.json")
        if run.get("tool") == tool and result.exists():
            rows.append((run, json.loads(result.read_text())))
    return sorted(rows, key=lambda row: (row[0]["startedAtUnix"], row[0]["runId"]))


def model_results(root, evidence, count):
    for _ in range(80):
        rows = [body for _, body in results(root, TOOL) if body.get("data", {}).get("rawAgentOutput") is not None]
        if len(rows) >= count and len(calls(evidence)) >= count:
            return rows
        time.sleep(0.25)
    raise AssertionError("Expected completed model result receipts")


def catalog_path(evidence):
    return Path(json.loads((evidence / "baseline.json").read_text())["path"])


def inspect(root, evidence, stage):
    expected = 0 if stage == "unbound" else (1 if stage == "invalid" else 2)
    assert len(calls(evidence)) == expected, (stage, calls(evidence))
    assert all(row["tools"] == row["liveProviderRequests"] == 0 and row["freshSession"] for row in calls(evidence))
    if stage in ["unbound", "invalid", "generated", "no-ack", "drift-refused"]:
        assert hashlib.sha256(catalog_path(evidence).read_bytes()).hexdigest() == json.loads((evidence / "baseline.json").read_text())["sha256"]
    if stage == "invalid":
        output = model_results(root, evidence, 1)[-1]
        assert output["status"] == "failed" and output["data"]["priorCatalogPreserved"]
    if stage == "generated":
        output = model_results(root, evidence, 2)[-1]
        assert output["status"] == "partial" and output["data"]["inspection"]["truncatedSourceFiles"] == 1
        assert output["data"]["entries"][0]["score"] == 0
        reference = output["data"]["draftRef"]
        save(evidence, "generated-draft", {"draftRef": reference, "sourceTreeHash": output["data"]["sourceTreeHash"]})
        for name, section in [("summary", "summary"), ("inputs", "inputs")]:
            command(evidence, name, "taint-iris-next:catalog-read", {"draftRef": reference, "section": section})
        command(evidence, "no-ack", "taint-iris-next:catalog-accept", {"draftRef": reference})
        command(evidence, "accept", "taint-iris-next:catalog-accept", {"draftRef": reference, "acknowledgePartial": True})
    if stage == "accepted":
        accepted = [body for _, body in results(root, "taint-iris-next:catalog-accept") if body.get("data", {}).get("status") == "accepted"]
        assert len(accepted) == 1, accepted
        pin = accepted[0]["data"]["catalogDigestRef"]
        save(evidence, "accepted-profile", {"catalogDigestRef": pin})
        command(evidence, "pinned", "taint-iris-next:catalog-read", {"catalogDigestRef": pin})
    if stage == "unreadable":
        read = results(root, "taint-iris-next:catalog-read")[-1][1]
        assert read["status"] == "failed" and read["data"]["status"] == "unreadable"
        reference = json.loads((evidence / "generated-draft.json").read_text())["draftRef"]
        command(evidence, "replace", "taint-iris-next:catalog-accept", {"draftRef": reference,
            "acknowledgePartial": True, "expectedActiveDigest": read["data"]["catalogDigestRef"]})
    if stage in ["exhausted", "restarted"]:
        blocked = [body for run, body in results(root, TOOL)
                   if run["status"] == "blocked" and "allowance exhausted" in body.get("summary", "")]
        assert len(blocked) == 1, blocked
    if stage not in ["drift-refused"]:
        assert (root / "owned café.c").read_text() == SOURCE
    with ledger(root, evidence) as db:
        names = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in names else 0
                  for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]}
    assert counts["finding_observations"] == counts["review_decisions"] == 0
    assert counts["investigation_call_reservations"] == expected
    assert not (root / ".kuzushi/cpg-rs").exists() and not (root / ".kuzushi/v3/batches").exists()
    save(evidence, stage + "-check", {"interceptedRequests": expected, "liveProviderRequests": 0, "counts": counts,
        "sourceUnchanged": stage != "drift-refused", "sourceExecuted": False})


def main():
    root, evidence = map(Path, sys.argv[1:3])
    stage = sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]))
    elif stage == "drift":
        (root / "owned café.c").write_text(SOURCE + "// Explicit owned source drift\n")
    elif stage == "restore":
        (root / "owned café.c").write_text(SOURCE)
    elif stage == "edit-active":
        catalog_path(evidence).write_text("Owned intervening active-catalog edit. Preserve until explicitly replaced.")
    else:
        inspect(root, evidence, stage)


if __name__ == "__main__":
    main()
