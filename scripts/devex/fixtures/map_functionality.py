"""Real deterministic Map artifacts from labeled source, no provider or source execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

SOURCE = """# Labeled static fixture. Never executed during this audit.
from flask import Flask
from fastapi import FastAPI
web = Flask(__name__)
api = FastAPI()
@web.get('/health')
def health(): pass
@api.post('/notes')
def notes(): pass
"""


def execute(root, evidence, home, name, tool, value, expected="completed"):
    source = evidence / (name + "-input.json")
    source.write_text(json.dumps(value) + "\n")
    environment = os.environ.copy()
    environment["HOME"] = str(home)
    for key in ["KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "NODE_OPTIONS", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
        environment.pop(key, None)
    result = subprocess.run([os.environ["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root), "run", tool, "--input", "@" + str(source)], env=environment, capture_output=True, text=True, timeout=60)
    output = json.loads(result.stdout)
    (evidence / (name + "-result.json")).write_text(result.stdout)
    (evidence / (name + "-stderr.txt")).write_text(result.stderr)
    assert output["status"] == expected, output
    assert result.returncode == (4 if expected == "partial" else 0), result.stderr
    return output["data"]


def seed(root, evidence, home):
    (root / "app.py").write_text(SOURCE)
    execute(root, evidence, home, "context", "context:build", {"enrichment": False})
    entries = execute(root, evidence, home, "entry-points", "entry-points:extract", {})
    routes = {entry["route"]: entry for entry in entries["entryPoints"] if entry.get("route")}
    assert routes["/health"]["framework"] == "Flask"
    assert routes["/notes"]["framework"] == "FastAPI"
    model = execute(root, evidence, home, "map", "threat-model:build", {"pipeline": "deterministic", "offline": True, "variantScan": False}, "partial")
    assert model["document"]["dfd"]["nodes"] and model["document"]["dfd"]["flows"]
    (evidence / "source-before.sha256").write_text(hashlib.sha256((root / "app.py").read_bytes()).hexdigest())
    (evidence / "map-ref.json").write_text(json.dumps(model["modelRef"]))
    verify(root, evidence)


def verify(root, evidence):
    assert hashlib.sha256((root / "app.py").read_bytes()).hexdigest() == (evidence / "source-before.sha256").read_text()
    with sqlite3.connect(root.joinpath(".kuzushi/v3/index.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
        for table in ["investigation_call_reservations", "investigation_work_attempts"]:
            if table in tables:
                assert connection.execute("select count(*) from " + table).fetchone()[0] == 0
    (evidence / "map-check.json").write_text(json.dumps({"sourceUnchanged": True, "providerCalls": 0, "sourceExecuted": False, "generatedMapStatus": "partial", "sourceFrameworks": {"/health": "Flask", "/notes": "FastAPI"}}, indent=2) + "\n")


if __name__ == "__main__":
    root, evidence, stage = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if stage == "seed":
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence)
