"""Owned inert archive and decompiler/code-rule stubs. No real APK tool or model runs."""
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from advisory_observations import decision_digest
from reviewed_lessons import prepare

TOOL = "android-apk:scan"


def script(evidence, name, body):
    path = evidence / (name + "-stub")
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o700)
    return str(path)


def seed(root, evidence):
    prepare(root, evidence)
    (evidence / "decision-before.sha256").write_text(decision_digest(root))
    apk = evidence / "owned.apk"
    apk.write_bytes(b"PK\x03\x04" + bytes(26))
    unzip = script(evidence, "unzip", r'''
if [ "$1" = '-l' ]; then
  printf 'Archive: owned fixture\n Length Date Time Name\n---------\n 4 2026-10-14 00:00 owned.txt\n---------\n'; exit 0
fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-d' ]; then shift; out="$1"; fi
  shift
done
mkdir -p "$out/lib"; printf 'Owned raw text' > "$out/owned.txt"
''')
    jadx = script(evidence, "jadx", r'''
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-d' ]; then shift; out="$1"; fi
  shift
done
mkdir -p "$out/sources"; printf '// Owned derived text. Never executed.\n' > "$out/sources/Owned.java"
''')
    apktool = script(evidence, "apktool", r'''
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-o' ]; then shift; out="$1"; fi
  shift
done
mkdir -p "$out/res/xml"
printf '%s\n' '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="owned.greeting"><application android:debuggable="true" android:allowBackup="false" android:usesCleartextTraffic="false"/></manifest>' > "$out/AndroidManifest.xml"
printf '%s\n' '<network-security-config><base-config cleartextTrafficPermitted="false"/></network-security-config>' > "$out/res/xml/network_security_config.xml"
printf '%s\n' '<paths><files-path name="owned" path="owned"/></paths>' > "$out/res/xml/file_paths.xml"
''')
    semgrep = script(evidence, "code", r'''printf '{"results":[],"errors":[{"message":"Labeled partial code inspection","type":"Warning"}]}' ''')
    value = {"apk": str(apk), "decompiler": "both", "timeoutMs": 2000, "maxApkBytes": 1024,
        "unzipBin": unzip, "jadxBin": jadx, "apktoolBin": apktool, "semgrepBin": semgrep}
    (evidence / "scan.txt").write_text("run " + TOOL + " " + json.dumps(value))
    value = dict(value, timeoutMs=50, unzipBin=script(evidence, "deadline", "exec sleep 5"))
    (evidence / "deadline.txt").write_text("run " + TOOL + " " + json.dumps(value))
    value = dict(value, unzipBin=str(evidence / "absent-unzip"))
    (evidence / "missing.txt").write_text("run " + TOOL + " " + json.dumps(value))
    (evidence / "apk-before.sha256").write_text(hashlib.sha256(apk.read_bytes()).hexdigest())


def result_for(root):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        rows = [(p.parent, json.loads(p.read_text())) for p in (root / ".kuzushi/v3/runs").glob("*/run.json")]
        rows = [(p, r) for p, r in rows if r.get("tool") == TOOL and r.get("status") == "partial"]
        if len(rows) == 1:
            path, run = rows[0]
            return path, run, json.loads((path / "result.json").read_text())
        time.sleep(.05)
    raise AssertionError(rows)


def verify(root, evidence, stage):
    assert decision_digest(root) == (evidence / "decision-before.sha256").read_text()
    assert hashlib.sha256((root / "hello.txt").read_bytes()).hexdigest() == (evidence / "source-before.sha256").read_text()
    active = json.loads((evidence / "active-before.json").read_text())
    assert hashlib.sha256(Path(active["path"]).read_bytes()).hexdigest() == active["sha256"]
    assert hashlib.sha256((evidence / "owned.apk").read_bytes()).hexdigest() == (evidence / "apk-before.sha256").read_text()
    path, run, result = result_for(root)
    data = result["data"]
    assert not run.get("phase") and result["status"] == "partial"
    assert data["coverage"]["complete"] is False and data["sourceVerified"] is False
    assert data["inputRecheck"] == "matched" and data["inputReceipt"]["decompiledSourceVerified"] is False
    assert data["inputReceipt"]["sha256"] == "sha256:" + (evidence / "apk-before.sha256").read_text()
    assert data["totals"]["findings"] > 0
    assert any(row["name"] == "code-scan" and row["status"] == "partial" for row in data["stages"])
    assert "Labeled partial code inspection" in json.dumps(result["errors"])
    saved = evidence / "result.sha256"
    digest = hashlib.sha256((path / "result.json").read_bytes()).hexdigest()
    if saved.exists():
        assert saved.read_text() == digest
    else:
        saved.write_text(digest)
        (evidence / "replay.txt").write_text("replay " + run["runId"])
        manifest = root / "android-decompiled/apktool/AndroidManifest.xml"
        (evidence / "derived-before.sha256").write_text(hashlib.sha256(manifest.read_bytes()).hexdigest())
    assert hashlib.sha256((root / "android-decompiled/apktool/AndroidManifest.xml").read_bytes()).hexdigest() == (evidence / "derived-before.sha256").read_text()
    if stage in ["failure", "restart"]:
        rows = [json.loads(p.read_text()) for p in (root / ".kuzushi/v3/runs").glob("*/result.json")]
        assert any(row.get("status") == "failed" and "deadline" in json.dumps(row) for row in rows)
    (evidence / (stage + "-check.json")).write_text(json.dumps({"partialRuns": 1, "providerCalls": 0,
        "realDecompilerCalls": 0, "sourceExecution": False, "observationsAreSynthetic": True,
        "originalSourceUnchanged": True, "exactHumanDecisionPreserved": True,
        "activeContextUnchanged": True, "archiveBytesUnchanged": True, "phaseContinuation": False}, indent=2) + "\n")


if __name__ == "__main__":
    stage, root, evidence = sys.argv[1:]
    root, evidence = Path(root).resolve(), Path(evidence).resolve()
    if stage == "seed":
        seed(root, evidence)
    else:
        verify(root, evidence, stage)
