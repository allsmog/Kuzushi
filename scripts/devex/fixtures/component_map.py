"""One owned component, no invented flow. No model calls or source execution."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from secret_settings import ledger


def save(folder, name, value):
    (folder / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def seed(root, evidence, home):
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "README.md").write_text("# Owned component fixture\nNo application behavior or runtime data flow is established.\n")
    (root / "Cargo.lock").write_text('# Owned inert declaration\nversion = 3\n')
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("")
    document = {"title":"Single owned component", "systemContext":"Owned dependency metadata. Deployment and runtime behavior remain unassessed.",
        "dfd":{"nodes":[{"id":"lock","name":"Declared lockfile","type":"data-store","trustZone":"repository","description":"Cargo.lock records owned dependency metadata.","purpose":"Supports owner review of dependency declarations."}],"flows":[],"trustBoundaries":[]},
        "attackSurface":{"entryPoints":[{"id":"infra-Cargo.lock","title":"Dependency declarations","filePath":"Cargo.lock","startLine":1,"targetElementIds":["lock"]}]},
        "threats":[{"id":"owner-review","entryPointId":"infra-Cargo.lock","title":"Dependency owner review","description":"Declarations require owner review before drawing deployment or runtime conclusions.","targetElementIds":["lock"]}],
        "openQuestions":[{"id":"deployment","question":"Does this metadata describe any deployed artifact?","targetElementIds":["lock"]}],"summary":{}}
    (root / ".kuzushi").mkdir(exist_ok=True)
    save(root / ".kuzushi", "component-context", document)
    beta = json.loads(json.dumps(document))
    beta["title"] = "Alternate active context"
    beta["systemContext"] = "Alternate source description. It must not replace the accepted Map context."
    beta["dfd"]["nodes"][0]["name"] = "Alternate metadata label"
    save(root / ".kuzushi", "alternate-context", beta)
    (evidence / "home.txt").write_text(str(home))
    save(evidence,"source-before",source_hashes(root))


def source_hashes(root):
    return {name:hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ["README.md","Cargo.lock"]}


def activate_alternate(root, evidence):
    env = dict(os.environ,HOME=(evidence / "home.txt").read_text())
    result = subprocess.run([env["KUZUSHI_NATIVE_BIN"],"--plain","--target",str(root),"run","threat-model:import","--input",json.dumps({"path":str(root / ".kuzushi/alternate-context.json"),"activate":True,"label":"Alternate active context"})],env=env,capture_output=True,text=True,timeout=30)
    (evidence / "alternate.stdout.json").write_text(result.stdout)
    (evidence / "alternate.stderr.txt").write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value["status"] == "completed" and value["data"]["verification"]["verdict"] == "verified",value
    save(evidence,"alternate-ref",value["data"]["modelRef"])


def verify(root, evidence, stage):
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    with ledger(root,evidence) as database:
        tables = {row[0] for row in database.execute("select name from sqlite_master where type='table'")}
        counts = {name:database.execute("select count(*) from "+name).fetchone()[0] if name in tables else 0
                  for name in ["finding_observations","investigation_call_reservations","investigation_work_attempts","review_decisions"]}
    assert all(value == 0 for value in counts.values()),counts
    manifest = json.loads((root / ".kuzushi/threat-models/manifest.json").read_text())
    if stage == "accepted":
        assert manifest.get("active") is None
    else:
        reference = json.loads((evidence / "alternate-ref.json").read_text())
        assert manifest["active"]["modelId"] == reference["modelId"]
        assert manifest["active"]["revisionId"] == reference["revisionId"]
    runs = []
    for path in (root / ".kuzushi/v3/runs").glob("*/run.json"):
        run = json.loads(path.read_text())
        if run.get("tool") == "threat-model:import":
            value = json.loads(path.with_name("result.json").read_text())
            doc = value["data"]["document"]
            assert len(doc["dfd"]["nodes"]) == 1 and doc["dfd"]["flows"] == []
            assert value["data"]["verification"]["verdict"] == "verified"
            runs.append(value)
    assert len(runs) == (1 if stage == "accepted" else 2)
    save(evidence,stage+"-verified",{"counts":counts,"sourceUnchanged":True,"modelCalls":0,"sourceExecuted":False,"flowCount":0,"activeContext":manifest.get("active")})


if __name__ == "__main__":
    root,evidence,stage = Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
    if stage == "seed": seed(root,evidence,Path(sys.argv[4]).resolve())
    elif stage == "alternate": activate_alternate(root,evidence)
    else: verify(root,evidence,stage)
