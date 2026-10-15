"""Measure real exact-scope Semgrep starts over owned inert source, never executed."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from installed_scope_study import native, save


def source_hashes(root):
    return {str(path.relative_to(root)):hashlib.sha256(path.read_bytes()).hexdigest()
            for directory in ["scope","other"] for path in (root / directory).glob("*.py")}


def install_single_worker_observer(evidence):
    binary = shutil.which("semgrep")
    assert binary,"Installed Semgrep is required"
    wrapper = evidence / "observed-semgrep"
    wrapper.write_text('#!' + sys.executable + '\nimport json,os,sys,time\nargs=sys.argv[1:]\nif "--jobs" not in args:\n args=["--jobs","1",*args]\nwith open(' + repr(str(evidence / "scanner-starts.jsonl")) + ',"a") as out:\n out.write(json.dumps({"argv":args,"pid":os.getpid(),"startMonoNs":time.monotonic_ns()})+"\\n")\nos.execv(' + repr(binary) + ',[' + repr(binary) + ',*args])\n')
    wrapper.chmod(0o755)
    return wrapper


def seed(root, evidence, home):
    assert root.name == "fixture-target" and root.parent == evidence
    root.mkdir(parents=True, exist_ok=True)
    for name in ["app.py","config.env"]:
        (root / name).unlink(missing_ok=True)
    for directory in ["scope","other"]:
        (root / directory).mkdir(exist_ok=True)
    files = [f"file-{index:04}.py" for index in range(1021)] + ["[route].py","space file.py","-option.py","zz-last.py"]
    for name in files:
        marker = "OWNER_POLICY_REVIEW" if name == "zz-last.py" else "ordinary notice"
        (root / "scope" / name).write_text('# Owned inert text. Never execute.\nprint("' + marker + '")\n')
    (root / "other/outside.py").write_text('# Owned unselected text. Never execute.\nprint("OWNER_POLICY_REVIEW")\n')
    home.mkdir(parents=True,exist_ok=True)
    (evidence / "runtime-home.txt").write_text(str(home))
    rules = evidence / "local-rules.yaml"
    rules.write_text('rules:\n  - id: owned-policy-marker\n    languages: [python]\n    severity: INFO\n    message: Owned inert policy marker needs an owner decision\n    pattern: print("OWNER_POLICY_REVIEW")\n')
    wrapper = install_single_worker_observer(evidence)
    scopes = [{"id":name,"name":label,"paths":[path],"rationale":"Explicit owned source boundary.","sharedDependencies":[],"openQuestions":[]}
        for name,label,path in [("selected","Selected policy text","scope"),("unselected","Unselected sibling","other")]]
    draft = {"schemaVersion":1,"scopes":scopes,"sharedScope":None,"sharedDiscovery":False,"exclusions":[]}
    created = native(root,evidence,"created",["run","pack:scopes","--input",json.dumps({"operation":"create","draft":draft})])["data"]
    accepted = native(root,evidence,"accepted",["run","pack:scopes","--input",json.dumps({"operation":"accept","proposalRef":created["reference"],
        "acknowledgements":{"inventoryLimitations":True,"overlappingDiscovery":False,"exclusions":False}})])["data"]
    assert accepted["coverage"]["discoveryMembers"]["selected"]["total"]==1025
    scan = {"taskMode":"manual","tasks":["semgrep"],"semgrepBinary":str(wrapper),"semgrepConfig":[str(rules)],
        "semgrepTimeoutMs":60000,"threatModelRef":None,"scanContextRef":None,"scanScopeRef":{"proposal":accepted["reference"],"scopeId":"selected"}}
    save(evidence,"scan-input",scan)
    save(evidence,"source-before",source_hashes(root))


def measure(root,evidence,home,label):
    before = json.loads((evidence / "source-before.json").read_text())
    assert source_hashes(root)==before
    log = evidence / "scanner-starts.jsonl"
    offset = len(log.read_text().splitlines()) if log.exists() else 0
    scan = json.loads((evidence / "scan-input.json").read_text())
    env = dict(os.environ,HOME=str(home),SEMGREP_ENABLE_VERSION_CHECK="0")
    for key in ["OPENAI_API_KEY","ANTHROPIC_API_KEY","KUZUSHI_MODEL","KUZUSHI_LANGGRAPH_BRIDGE","NODE_OPTIONS","SEMGREP_APP_TOKEN","SEMGREP_AGENT_TOKEN"]:
        env.pop(key,None)
    started = time.monotonic_ns()
    result = subprocess.run([env["KUZUSHI_NATIVE_BIN"],"--plain","--target",str(root),"run","sast:scan","--input",json.dumps(scan)],env=env,capture_output=True,text=True,timeout=110)
    elapsed = (time.monotonic_ns()-started)/1_000_000
    (evidence / (label+".stdout.json")).write_text(result.stdout)
    (evidence / (label+".stderr.txt")).write_text(result.stderr)
    assert result.returncode==0,result.stderr
    value = json.loads(result.stdout)
    assert value["status"]=="completed",value.get("summary")
    findings=value["data"]["coreFindings"]
    assert len(findings)==1 and findings[0]["file_path"].endswith("scope/zz-last.py"),findings
    rows=[json.loads(line) for line in log.read_text().splitlines()[offset:]]
    analyses=[row for row in rows if "--json" in row["argv"]]
    submitted=[arg for row in analyses for arg in row["argv"][row["argv"].index("--")+1:]]
    expected=sorted(name for name in before if name.startswith("scope/"))
    assert sorted(submitted)==expected and len(set(submitted))==1025
    assert source_hashes(root)==before
    save(evidence,label+"-measurement",{"elapsedMs":elapsed,"scannerProcesses":len(analyses),"submittedFiles":len(submitted),
        "batchSizes":[len(row["argv"])-row["argv"].index("--")-1 for row in analyses],"finding":"scope/zz-last.py",
        "scanWorkers":[row["argv"][row["argv"].index("--jobs")+1] if "--jobs" in row["argv"] else "implicit" for row in analyses],
        "sourceExecuted":False,"sourceFilesUnchanged":len(before),"providerRequests":0,"sourceAuthenticationIncludedInWallTime":True})


if __name__ == "__main__":
    root,evidence,home=[Path(value).resolve() for value in sys.argv[1:4]]
    if sys.argv[4]=="seed": seed(root,evidence,home)
    else: measure(root,evidence,home,sys.argv[4])
