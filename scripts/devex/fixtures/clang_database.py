"""Owned compiler-input checks using real read-only clangd and intercepted inference."""
import hashlib
import json
import shutil
import sys
from pathlib import Path

import taint_catalog as base
from rejected_context import execute, source_bytes
from secret_settings import ledger, save

TOOL = "uaf-hunt:hunt"
INVESTIGATION = "owned-clang-selection"


def compiler_inputs(root, evidence):
    source = root / "owned café.c"
    source.write_text("#if OWNED_SELECTED\nint owned_selected;\n#else\nint unselected;\n#endif\nint inspected(void) { return owned_selected; }\n")
    (root / ".clangd").write_text("CompileFlags:\n  Remove: [-DOWNED_SELECTED=*]\n  Add: [-DOWNED_SELECTED=0]\n")
    command = {"directory": str(root.resolve()), "file": source.name,
               "arguments": ["clang", "-DOWNED_SELECTED=0", "-c", source.name]}
    (root / "compile_commands.json").write_text(json.dumps([command], ensure_ascii=False))
    command["arguments"][1] = "-DOWNED_SELECTED=1"
    selected = (evidence / "chosen compiler #1.json").resolve()
    selected.write_text(json.dumps([command], ensure_ascii=False))
    (evidence / "selected-original.json").write_bytes(selected.read_bytes())
    save(evidence, "selected-before", {"path": str(selected), "sha256": hashlib.sha256(selected.read_bytes()).hexdigest(),
                                       "bytes": selected.stat().st_size})
    return selected


def seed(root, evidence, home):
    base.seed(root, evidence, home)
    selected = compiler_inputs(root, evidence)
    shutil.copyfile(Path(__file__).with_name("clang_database_provider.mjs"), evidence / "provider.mjs")
    save(evidence, "source-before", source_bytes(root))
    base.command(evidence, "approval", "campaign:approve-allowance", {
        "investigationId": INVESTIGATION, "expectedRevision": 0, "model": base.MODEL,
        "maxProviderCalls": 5, "protectedReviewCalls": 1,
        "reason": "Two fixed source-only compiler-input tests, shell then headless, one worker and four intercepted requests with real read-only clangd. No live model, target execution or follow-up jobs. One protected Review call."})
    for name in ["unbound", "generate", "exhausted"]:
        value = {"externalCompileCommandsPath": str(selected), "clangTimeoutSecs": 10,
                 "maxAgentSteps": 2, "maxFindings": 1}
        if name != "unbound":
            value["allowanceRef"] = {"schemaVersion": 1, "investigationId": INVESTIGATION,
                                     "revision": 1, "workId": "compiler-" + name}
        base.command(evidence, name, TOOL, value)
    base.command(evidence, "status", "campaign:allowance", {"investigationId": INVESTIGATION})


def inspect(root, evidence, stage):
    assert source_bytes(root) == json.loads((evidence / "source-before.json").read_text())
    expected = 0 if stage == "unbound" else 2 if stage == "generated" else 4
    calls = base.calls(evidence)
    assert len(calls) == expected and all(row["liveProviderRequests"] == 0 for row in calls), calls
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
                  for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]}
        assert counts["finding_observations"] == counts["review_decisions"] == 0
        assert counts["investigation_call_reservations"] == expected
        if expected:
            for raw, review, settled in db.execute("select call_json,review,settled_at from investigation_call_reservations"):
                assert json.loads(raw)["work"] == "discovery" and review == 0 and settled is not None
    proof = {"interceptedRequests": expected, "liveProviderRequests": 0, "sourceUnchanged": True,
             "sourceExecuted": False, "newJobs": 0, "counts": counts}
    if expected:
        verify_navigation(root, evidence, calls, proof)
    if stage in ["exhausted", "restarted"]:
        blocked = [body for _, body in base.results(root, TOOL) if body["status"] == "blocked"]
        assert len(blocked) == 2, blocked
        assert sum("needs an approved investigation allowance" in body["summary"] for body in blocked) == 1
        assert sum("allowance exhausted: 4 calls committed" in body["summary"] for body in blocked) == 1
        proof["refusedInvocations"] = len(blocked)
    assert not (root / "owned.o").exists() and not (root / ".kuzushi/v3/batches").exists()
    save(evidence, stage + "-check", proof)


def verify_navigation(root, evidence, calls, proof):
    for index in range(0,len(calls),2):
        assert calls[index+1]["navigationLine"] == 2 and calls[index]["configurationChangedAfterCapture"]
    rows = [(run, body) for run, body in base.results(root, TOOL) if "compileDatabase" in body.get("data", {})]
    assert len(rows) == len(calls)//2, rows
    for run, result in rows:
        verify_result(evidence, run, result)
    run, result = rows[-1]
    (evidence / "replay-command.txt").write_text("replay " + run["runId"])
    proof.update({"runId": run["runId"], "reportStatus": "completed", "navigationLine": 2,
                  "configurationChangedAfterCapture": True, "compileDatabase": result["data"]["compileDatabase"],
                  "completedInvocations": len(rows)})


def verify_result(evidence, run, result):
    data, before = result["data"], json.loads((evidence / "selected-before.json").read_text())
    assert run["status"] == result["status"] == "completed"
    assert data["count"] == 0 and data["clangToolCalls"] == 1 and data["repoToolCalls"] == 0
    assert data["stepsUsed"] == data["maxAgentSteps"] == 2
    receipt = data["compileDatabase"]
    assert receipt["sourcePath"] == before["path"] and receipt["sourceSha256"] == before["sha256"]
    assert receipt["sourceBytes"] == before["bytes"] and receipt["entries"] == 1
    assert hashlib.sha256(Path(before["path"]).read_bytes()).hexdigest() != receipt["sourceSha256"]
    assert result.get("costUsd") is None and data.get("costUsd") is None and result["providerSpendUnresolved"]
    assert "omits command contents and the model prompt" in data["inputDocument"]["text"]
    transcript = Path(data["persisted"]["transcriptPath"]).read_text()
    assert "locations" in transcript and not data.get("firstClangError")


def headless(root, evidence, home):
    before = json.loads((evidence / "selected-before.json").read_text())
    Path(before["path"]).write_bytes((evidence / "selected-original.json").read_bytes())
    execute(root, home, evidence, "headless-compiler", TOOL, {
        "externalCompileCommandsPath": before["path"], "clangTimeoutSecs": 10, "maxAgentSteps": 2,
        "maxFindings": 1, "allowanceRef": {"schemaVersion": 1, "investigationId": INVESTIGATION,
            "revision": 1, "workId": "compiler-headless"}})
    inspect(root,evidence,"headless")


if __name__ == "__main__":
    root, evidence = map(Path, sys.argv[1:3])
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]))
    elif sys.argv[3] == "headless":
        headless(root,evidence,Path(sys.argv[4]))
    else:
        inspect(root, evidence, sys.argv[3])
