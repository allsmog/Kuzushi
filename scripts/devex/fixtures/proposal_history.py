"""Owned proposal-history metadata fixture. No models, scanners or source execution."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def queue_path(root):
    return root / '.kuzushi/v3/strategy-queue.jsonl'


def rows(root):
    return [json.loads(line) for line in queue_path(root).read_text().splitlines() if line.strip()]


def generate(root, evidence, name):
    result = subprocess.run([os.environ['KUZUSHI_NATIVE_BIN'], '--target', str(root), 'run',
        'module-recommender:recommend', '--input', '{}'], text=True, capture_output=True, timeout=60)
    (evidence / (name + '.stdout.json')).write_text(result.stdout)
    (evidence / (name + '.stderr.txt')).write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value['data']['rankingMode'] == 'deterministic'
    assert value['data']['model'] is None and value['data']['costUsdExact'] is True
    run = (root / '.kuzushi/v3/latest').read_text().strip()
    artifact = json.loads((root / '.kuzushi/v3/runs' / run / 'strategy.json').read_text())
    assert artifact['strategyProposals']
    assert all(row['status'] == 'proposed' for row in artifact['strategyProposals'])
    save(evidence, name + '-receipt', {'runId':run,'proposalCount':len(artifact['strategyProposals']),
        'providerRequests':0,'scannerJobs':0,'allPublishedDraftsUnapproved':True})
    return run


def prepare(root, evidence, home):
    for name in ['app.py', 'config.env']:
        (root / name).unlink(missing_ok=True)
    (root / 'Cargo.toml').write_text('[package]\nname="owned-history"\nversion="0.0.0"\nedition="2021"\n')
    (root / 'owned.rs').write_text('// Owned inert proposal fixture. Never executed.\n')
    config = home / '.kuzushi/v3/config.toml'
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model="openai-codex:gpt-5.5"\n[runtime]\nthinking_level="medium"\n')
    generate(root, evidence, 'initial')
    values = rows(root)
    assert len(values) >= 4
    by_tool = {row['tool']:row for row in values}
    approved = by_tool['cargo-audit:scan']
    rejected = by_tool['dep-hygiene:check']
    done = by_tool['secret-scan:scan']
    failed = by_tool['semgrep:scan']
    for row in [approved, rejected, done, failed]:
        row['rationale'] = 'Owned labeled metadata fixture; not actual scanner evidence.'
    approved['approvedCostUsd'] = 0.5
    approved['correctedStrategy'] = 'operator-retained-context-preference'
    done.update(status='done', approvedCostUsd=0.6, actualCostUsd=0.2,
        findingsCount=2, confirmedCount=1, resultRunId='owned-synthetic-result')
    failed.update(status='failed', actualCostUsd=0.1,
        resultRunId='owned-synthetic-failure-run', failure='OWNED_SYNTHETIC_FAILURE_EVIDENCE')
    queue_path(root).write_text(''.join(json.dumps(row) + '\n' for row in values))
    save(evidence, 'state', {'config':str(config),'configHash':hashlib.sha256(config.read_bytes()).hexdigest(),
        'sourceHash':hashlib.sha256((root / 'owned.rs').read_bytes()).hexdigest(),
        'syntheticOutcomeMetadata':True,'syntheticIds':False,'realRecommendationGeneration':True})


def decisions(root, evidence):
    values = rows(root)
    by_id = {row['id']:row for row in values}
    assert by_id['review-cargo-audit-scan']['status'] == 'approved'
    assert by_id['review-dep-hygiene-check']['status'] == 'rejected'
    assert by_id['review-cargo-audit-scan']['approvedCostUsd'] == 0.5
    save(evidence, 'reviewed-history', values)


def regenerate(root, evidence):
    original = json.loads((evidence / 'reviewed-history.json').read_text())
    generate(root, evidence, 'regenerated')
    values = rows(root)
    by_id = {row['id']:row for row in values}
    for old in original:
        assert by_id[old['id']] == old, old['id']
    old_ids = {row['id'] for row in original}
    new = [row for row in values if row['id'] not in old_ids]
    assert new and all(row['status'] == 'proposed' for row in new)
    assert all(row.get('approvedCostUsd') is None and row.get('actualCostUsd') is None
        and row.get('resultRunId') is None for row in new)
    save(evidence, 'regeneration-check', {'allPriorRecordsUnchanged':True,
        'newDrafts':len(new),'newApprovals':0,'newActualCosts':0,'newOutcomeReferences':0})
    verify(root, evidence, 'regenerated')


def verify(root, evidence, stage):
    state = json.loads((evidence / 'state.json').read_text())
    assert hashlib.sha256(Path(state['config']).read_bytes()).hexdigest() == state['configHash']
    assert hashlib.sha256((root / 'owned.rs').read_bytes()).hexdigest() == state['sourceHash']
    original = json.loads((evidence / 'reviewed-history.json').read_text())
    by_id = {row['id']:row for row in rows(root)}
    assert all(by_id[row['id']] == row for row in original)
    database = root / '.kuzushi/v3/index.sqlite3'
    if database.exists():
        with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
            tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            for table in ['finding_observations','review_decisions','investigation_call_reservations','investigation_work_attempts']:
                if table in tables:
                    assert db.execute('select count(*) from ' + table).fetchone()[0] == 0, table
    assert not (root / '.kuzushi/v3/campaigns').exists()
    save(evidence, stage + '-check', {'historyPreserved':True,'providerRequests':0,'scannerJobs':0,
        'sourceExecuted':False,'newFindingObservations':0,'syntheticOutcomeMetadata':True,
        'configurationUnchanged':True,'ownedSourceUnchanged':True})


root, evidence = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
action = sys.argv[3]
if action == 'prepare':
    prepare(root, evidence, Path(sys.argv[4]).resolve())
elif action == 'decisions':
    decisions(root, evidence)
elif action == 'regenerate':
    regenerate(root, evidence)
else:
    verify(root, evidence, action)
