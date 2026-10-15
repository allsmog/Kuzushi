"""Installed offline lockfile inspection. Owned metadata is never built or run."""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from secret_settings import ledger

LOCK = '# Owned hypothetical dependency metadata. Never built or executed.\nversion = 3\n\n[[package]]\nname = "time"\nversion = "0.1.40"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'


def save(folder, name, value):
    (folder / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def hashes(root):
    files = [path for path in root.rglob("*") if path.is_file()
             and not {".git", ".kuzushi"}.intersection(path.relative_to(root).parts)]
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(files)}


def seed(root, evidence, home):
    binary = shutil.which("cargo-audit")
    assert binary, "Installed standalone cargo-audit is required"
    cache = Path.home() / ".cargo/advisory-db"
    assert cache.is_dir(), "An existing local advisory database is required; no fetch is permitted"
    database = evidence / "advisory-db"
    shutil.copytree(cache, database, ignore=shutil.ignore_patterns("*.lock"))
    for name in ["app.py", "config.env"]:
        (root / name).unlink(missing_ok=True)
    (root / "README.md").write_text("# Owned dependency metadata\nThis hypothetical lockfile fixture has no application source, runtime reachability or executed vulnerability.\n")
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = "openai-codex:gpt-5.5"\n[runtime]\nthinking_level = "medium"\n')
    probe = subprocess.run([binary, "audit", "--json", "--file", "-", "--db", str(database), "--no-fetch", "--no-yanked", "--stale"], input=LOCK, text=True, capture_output=True, cwd=evidence, timeout=30)
    (evidence / "installed-probe.stdout.json").write_text(probe.stdout)
    (evidence / "installed-probe.stderr.txt").write_text(probe.stderr)
    report = json.loads(probe.stdout)
    entries = report["vulnerabilities"]["list"]
    assert probe.returncode == 1 and len(entries) == 1, report
    assert entries[0]["advisory"]["id"] == "RUSTSEC-2020-0071", report
    save(evidence, "scanner", {"binary":binary,"sha256":hashlib.sha256(Path(binary).read_bytes()).hexdigest(),"advisoryDb":str(database),"version":subprocess.check_output([binary,"--version"],text=True).strip(),"databaseSourceHashes":hashes(database)})
    (evidence / "missing-command.txt").write_text('run cargo-audit:scan {"offline":true}')
    (evidence / "binary-setting.txt").write_text("set cargoAuditBinary " + json.dumps(binary))
    (evidence / "database-setting.txt").write_text("set cargoAuditAdvisoryDb " + json.dumps(str(database)))
    (evidence / "home.txt").write_text(str(home))


def install_source(root, evidence):
    (root / "Cargo.lock").write_text(LOCK)
    (root / ".cargo").mkdir(exist_ok=True)
    (root / ".cargo/audit.toml").write_text('[advisories]\nignore = ["RUSTSEC-2020-0071"]\n')
    doc = {"title":"Owned dependency metadata context", "systemContext":"Cargo.lock declares time 0.1.40 in an owned hypothetical fixture. The scanner inspects dependency advisories from a copied local database. No application source, runtime reachability or vulnerability execution is established. The target-local audit configuration must not suppress operator-selected inspection.",
           "dfd":{"nodes":[{"id":"lock","name":"Declared lockfile","type":"data-store","trustZone":"repository","description":"Cargo.lock contains hypothetical time 0.1.40 dependency metadata.","purpose":"Supports dependency advisory inspection without building or running source."}],"flows":[],"trustBoundaries":[]},
           "attackSurface":{"entryPoints":[{"id":"infra-Cargo.lock","filePath":"Cargo.lock","startLine":1,"title":"Declared dependency metadata","targetElementIds":["lock"]}]},
           "threats":[{"id":"dependency-owner-review","entryPointId":"infra-Cargo.lock","title":"Declared dependency review","description":"A lockfile declaration can refer to a dependency with published advisories. Confirm actual package presence and application scope before drawing runtime conclusions.","targetElementIds":["lock"]}],
           "openQuestions":[{"id":"actual-dependency","question":"Does the hypothetical declared dependency correspond to any real deployed artifact? Runtime reachability is outside this exercise.","targetElementIds":["lock"]}],
           "summary":{"evidenceType":"Owned static dependency declaration; reachability unassessed."}}
    (root / ".kuzushi").mkdir(exist_ok=True)
    save(root / ".kuzushi", "manual-context", doc)
    save(evidence, "source-before", hashes(root))


def run_results(root, tool):
    return [(path.parent, json.loads(path.with_name("result.json").read_text()))
            for path in (root / ".kuzushi/v3/runs").glob("*/run.json")
            if json.loads(path.read_text()).get("tool") == tool and path.with_name("result.json").is_file()]


def counts(root, evidence):
    with ledger(root,evidence) as database:
        tables = {row[0] for row in database.execute("select name from sqlite_master where type='table'")}
        return {name:database.execute("select count(*) from " + name).fetchone()[0] if name in tables else 0
                for name in ["finding_observations","investigation_call_reservations","investigation_work_attempts","review_decisions"]}


def plan(root, evidence):
    plans = [json.loads(path.read_text()) for path in (root / ".kuzushi/v3/campaigns").glob("*/plan.json")]
    plans = [value for value in plans if value["kind"] == "scan-batch"]
    assert len(plans) == 1
    value = plans[0]
    assert len(value["jobs"]) == 3 and value["workers"] == 1
    settings = value["baseInput"]
    assert settings["tasks"] == ["cargo-audit"]
    assert settings["cargoAuditOffline"] and settings["cargoAuditAllowStale"]
    assert settings["cargoAuditTimeoutMs"] == 60000
    assert settings["cargoAuditMaxLockfileBytes"] == 1048576
    assert all(not settings[key] for key in ["triage","verify","autoPatch","patch","pocExecution","dynamicAnalysis"])
    assert settings["threatModelRef"]["revisionId"] and settings["scanContextRef"]["object"]["sizeBytes"] > 0
    assert value["equivalence"].get("model") is None
    (evidence / "resume-command.txt").write_text("batch " + value["campaignId"])
    return value


def inspect(root, evidence, stage):
    if stage == "missing":
        deadline = time.monotonic() + 20
        while not run_results(root,"cargo-audit:scan") and time.monotonic() < deadline:
            time.sleep(0.1)
        runs = run_results(root,"cargo-audit:scan")
        assert len(runs) == 1 and runs[0][1]["status"] == "failed"
        assert "regular Cargo.lock" in runs[0][1]["output"]
        assert counts(root,evidence)["finding_observations"] == 0
        save(evidence,"missing-verified",{"status":"failed","providerCalls":0,"sourceExecuted":False})
        return
    assert hashes(root) == json.loads((evidence / "source-before.json").read_text())
    scanner = json.loads((evidence / "scanner.json").read_text())
    assert hashes(Path(scanner["advisoryDb"])) == scanner["databaseSourceHashes"]
    value = plan(root,evidence)
    current = counts(root,evidence)
    if stage == "draft":
        assert current["finding_observations"] == current["investigation_call_reservations"] == 0
    else:
        queue = json.loads((root / ".kuzushi/v3/campaigns" / value["campaignId"] / "queue.json").read_text())
        assert len(queue["jobs"]) == 3 and all(job["state"] == "completed" and job["attempts"] == 1 for job in queue["jobs"].values())
        assert current["finding_observations"] == current["investigation_work_attempts"] == 3
        assert current["investigation_call_reservations"] == 0
        runs = run_results(root,"sast:scan")
        assert len(runs) == 3
        for _, result in runs:
            assert result["status"] == "completed" and result["data"]["nativeInspections"][0]["offline"]
        if stage in ["exported","restarted"]:
            report = json.loads((root / ".kuzushi/reports/findings.json").read_text())
            assert report["count"] == 1 and report["findings"][0]["reviewDecision"] == "deferred"
            assert "RUSTSEC-2020-0071" in json.dumps(report)
            accounting = report["metadata"]["investigation"]["allowance"]["currentInvestigation"]
            assert accounting["committedCalls"] == accounting["unresolvedCalls"] == 0
            assert accounting["limits"] == {"maxProviderCalls":1,"protectedReviewCalls":1}
    assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text()).get("active") is None
    save(evidence,stage+"-verified",{"counts":current,"sourceUnchanged":True,"databaseUnchanged":True,"sourceExecuted":False})


if __name__ == "__main__":
    root,evidence,stage = Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),sys.argv[3]
    if stage == "seed": seed(root,evidence,Path(sys.argv[4]).resolve())
    elif stage == "install": install_source(root,evidence)
    elif stage == "completed":
        deadline = time.monotonic() + 45
        while True:
            try: inspect(root,evidence,stage); break
            except (AssertionError,FileNotFoundError):
                if time.monotonic() >= deadline: raise
                time.sleep(0.1)
    else: inspect(root,evidence,stage)
