"""Passive import audit using labeled synthetic captures. No requests or source execution."""
import hashlib
import json
import os
import sys
from pathlib import Path

from secret_settings import ledger


def seed(root, evidence):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "README.md").write_text("Owned inert import fixture. Captures are labeled synthetic data; no service is contacted.\n")
    (root / ".kuzushi").mkdir(exist_ok=True)
    (root / ".kuzushi/scope.toml").write_text('[in_scope]\nhosts = ["owned.invalid"]\n')
    httpx = evidence / "owned httpx.jsonl "
    httpx.write_text(''.join(json.dumps(row) + '\n' for row in [
        {"url":"https://owned.invalid/public", "title":"Labeled synthetic recorded metadata", "status_code":200},
        {"url":"https://outside.invalid/ignored"}, {}]))
    broken = evidence / "broken.jsonl"
    broken.write_text(json.dumps({"url":"https://owned.invalid/retained", "title":"Labeled synthetic retained row"}) + '\ninvalid\n')
    har = evidence / "owned capture.har "
    har.write_text(json.dumps({"log":{"version":"1.2","entries":[
        {"request":{"method":"GET","url":"https://owned.invalid/public","headers":[]},"response":{"status":200,"headers":[]}},
        {"request":{"method":"GET","url":"https://outside.invalid/ignored","headers":[]},"response":{"status":200}},
        {"request":{"method":"GET","headers":[]},"response":{"status":200}}]}}))
    burp = evidence / "owned capture.xml "
    burp.write_text('<items><item><url>https://owned.invalid/burp</url><method>GET</method><status>200</status><request base64="false">GET /burp HTTP/1.1</request><response base64="false">HTTP/1.1 200 OK</response></item></items>')
    commands = {"httpx":("recon:import",{"tool":"httpx","path":str(httpx)}),
        "broken":("recon:import",{"tool":"httpx","path":str(broken)}),
        "har":("recon:import",{"tool":"har","path":str(har)}),
        "bounty-har":("bounty:import-har",{"path":str(har)}),
        "burp":("bounty:import-burp",{"path":str(burp)})}
    for name,(tool,args) in commands.items():
        (evidence / (name + "-command.txt")).write_text("run " + tool + " " + json.dumps(args))
    (evidence / "source-before.json").write_text(json.dumps({name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ["README.md", ".kuzushi/scope.toml"]}))


def verify(root, evidence, stage):
    assert {name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ["README.md", ".kuzushi/scope.toml"]} == json.loads((evidence / "source-before.json").read_text())
    workflow = root / ".kuzushi/v3/workflow"
    assert not any(p.read_bytes().strip() for p in workflow.glob("phase-attempts*.jsonl")), "import owns a phase attempt"
    assert not list((root / ".kuzushi/v3/campaigns").glob("*/plan.json"))
    with ledger(root,evidence) as db:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts", "review_decisions"]:
            if table in tables:
                assert db.execute("select count(*) from " + table).fetchone()[0] == 0
        hosts = db.execute("select count(*) from hosts").fetchone()[0]
        services = db.execute("select count(*) from services").fetchone()[0]
        assert hosts == services == 1
        observations = db.execute("select count(*) from finding_observations").fetchone()[0] if "finding_observations" in tables else 0
    expected = 0 if stage in ["httpx", "broken"] else (1 if stage == "har" else 3)
    assert observations == expected, (stage,observations)
    receipts = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/runs").glob("*/result.json")]
    httpx_receipts = [r for r in receipts if r.get("data", {}).get("skippedOutOfScope") == 1]
    assert any(r["data"].get("skippedUnusable") == 1 for r in httpx_receipts), "scope/unusable counts missing"
    if stage == "broken":
        failures = [r for r in receipts if r.get("status") == "failed"]
        assert any("Earlier saved evidence may remain" in json.dumps(r) and "line 2" in json.dumps(r) for r in failures)
    (evidence / (stage + "-check.json")).write_text(json.dumps({"phaseAttempts":0,"providerCalls":0,"workAttempts":0,"sourceExecuted":False,"networkRequests":0,
        "hosts":hosts,"services":services,"observations":observations,"capturesAreSynthetic":True},indent=2) + '\n')


if __name__ == "__main__":
    root,evidence,stage = Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]
    if stage == "seed":
        seed(root,evidence)
    else:
        verify(root,evidence,stage)
