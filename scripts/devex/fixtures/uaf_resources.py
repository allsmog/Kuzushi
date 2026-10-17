"""Bounded UAF navigation on inert owned source. No target code execution or live model."""
import json
import os
import re
import shutil
import sys
from pathlib import Path
import taint_catalog as base
from rejected_context import source_bytes
from secret_settings import ledger, save

TOOL = "uaf-hunt:hunt"
INVESTIGATION = "owned-uaf-resources"


def seed(root, evidence, home):
    base.seed(root, evidence, home)
    (root / "compile_commands.json").write_text("[]\n")
    shutil.copyfile(Path(__file__).with_name("uaf_resources_provider.mjs"), evidence / "provider.mjs")
    helper = evidence / "clang-helper.py"
    calls = str(evidence / "helper-calls.jsonl")
    tools = [{"name": name, "inputSchema": {"properties": {"compileCommandsPath": {"type": "string"}}}}
             for name in ["clang.definition", "clang.references", "clang.type_at", "clang.callers", "clang.callees"]]
    helper.write_text("#!/usr/bin/env python3\nimport json,os,sys,time\n"
        + "for line in sys.stdin:\n    request=json.loads(line)\n"
        + "    with open(" + json.dumps(calls) + ",'a') as log:\n"
        + "        log.write(json.dumps({'pid':os.getpid(),'method':request['method']})+'\\n')\n"
        + "    result={}\n"
        + "    if request['method']=='tools/list': result={'tools':" + repr(tools) + "}\n"
        + "    elif request['method']=='tools/call' and request['params']['name']=='clang.health': result={'structuredContent':{'ready':True,'missing':[]}}\n"
        + "    elif request['method']!='initialize': time.sleep(2)\n"
        + "    print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result}),flush=True)\n")
    helper.chmod(0o755)
    save(evidence, "source-before", source_bytes(root))
    base.command(evidence, "approval", "campaign:approve-allowance", {
        "investigationId": INVESTIGATION, "expectedRevision": 0, "model": base.MODEL,
        "maxProviderCalls": 3, "protectedReviewCalls": 1,
        "reason": "One fixed source-only resource test, one worker and two intercepted requests. A delayed local helper must time out. No live inference, target execution, follow-up jobs or source changes. One protected Review call."})
    for name in ["unbound", "generate", "exhausted"]:
        value = {"clang_timeout_secs": 1, "max_agent_steps": 2, "maxFindings": 1}
        if name != "unbound":
            value["allowanceRef"] = {"schemaVersion": 1, "investigationId": INVESTIGATION,
                "revision": 1, "workId": "uaf-" + name}
        base.command(evidence, name, TOOL, value)
    base.command(evidence, "status", "campaign:allowance", {"investigationId": INVESTIGATION})


def inspect(root, evidence, stage):
    assert source_bytes(root) == json.loads((evidence / "source-before.json").read_text())
    calls = base.calls(evidence)
    expected = 0 if stage == "unbound" else 2
    assert len(calls) == expected, calls
    assert all(row["liveProviderRequests"] == 0 for row in calls)
    with ledger(root, evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts = {name: db.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
                  for name in ["finding_observations", "review_decisions", "investigation_call_reservations", "investigation_work_attempts"]}
        assert counts["finding_observations"] == counts["review_decisions"] == 0
        assert counts["investigation_call_reservations"] == expected
        statuses = dict(db.execute("select run_id,status from run_states")) if "run_states" in tables else {}
        if expected:
            for raw, review, settled in db.execute("select call_json,review,settled_at from investigation_call_reservations"):
                assert json.loads(raw)["work"] == "discovery" and review == 0 and settled is not None
    proof = {"interceptedRequests": expected, "liveProviderRequests": 0, "counts": counts,
             "sourceUnchanged": True, "sourceExecuted": False, "newJobs": 0}
    if expected:
        rows = [(run, body) for run, body in base.results(root, TOOL) if "clangToolCalls" in body.get("data", {})]
        assert len(rows) == 1, rows
        run, result = rows[0]
        data = result["data"]
        assert run["status"] == result["status"] == "partial"
        assert data["count"] == 0 and data["clangToolCalls"] == 1 and data["repoToolCalls"] == 0
        assert data["clangTimeoutSecs"] == 1 and data["maxAgentSteps"] == data["stepsUsed"] == 2
        assert "timed out" in data["firstClangError"]
        assert result.get("costUsd") is None and data.get("costUsd") is None
        assert result["providerSpendUnresolved"] is True
        assert statuses[data["persisted"]["runId"]] == "partial"
        transcript = Path(data["persisted"]["transcriptPath"])
        assert transcript.is_file() and "timed out" in transcript.read_text()
        events = [json.loads(line) for line in (evidence / "helper-calls.jsonl").read_text().splitlines()]
        assert [row["method"] for row in events] == ["initialize", "tools/list", "tools/call", "tools/call"], events
        assert len({row["pid"] for row in events}) == 1
        try:
            os.kill(events[0]["pid"], 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError("Timed-out helper still exists")
        (evidence / "replay-command.txt").write_text("replay " + run["runId"])
        proof.update({"runId": run["runId"], "reportStatus": "partial", "findingRunStatus": "partial",
                      "helperReaped": True, "automaticHelperRestarts": 0})
    if stage in ["exhausted", "restarted"]:
        blocked = [body for run, body in base.results(root, TOOL) if run["status"] == "blocked"
                   and "allowance exhausted" in body.get("summary", "")]
        assert len(blocked) == 1
    if stage == "narrow":
        narrow(evidence)
    assert not (root / ".kuzushi/v3/batches").exists()
    save(evidence, stage + "-check", proof)


def narrow(evidence):
    paths = list(evidence.glob("*-result-40x12.txt")) + sorted(evidence.glob("*-reading-*-40x12.txt"))
    paths += list(evidence.glob("*-result-tail-40x12.txt"))
    covered, totals, body = set(), set(), []
    for path in paths:
        text = path.read_text()
        start, end, total = map(int, re.search(r"rows (\d+)-(\d+)/(\d+)", text).groups())
        totals.add(total)
        covered.update(range(start, end + 1))
        body.extend(text.splitlines()[2:2 + end - start + 1])
    assert len(totals) == 1
    total = totals.pop()
    assert covered == set(range(1, total + 1)), sorted(set(range(1, total + 1)) - covered)
    joined = " ".join(" ".join(body).split())
    for phrase in ["partial local analysis", "Unverified source-analysis candidates", "512 KiB",
                   "whole-repository analysis", "timed out", "coverage is not established"]:
        assert phrase in joined, phrase
    save(evidence, "narrow-reading", {"allRowsReached": True, "rowsCovered": total})


if __name__ == "__main__":
    root, evidence = map(Path, sys.argv[1:3])
    if sys.argv[3] == "seed":
        seed(root, evidence, Path(sys.argv[4]))
    else:
        inspect(root, evidence, sys.argv[3])
