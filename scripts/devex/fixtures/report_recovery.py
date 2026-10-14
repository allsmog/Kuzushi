"""Owned report-choice recovery fixture. No inference, scanning or source execution."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path


def save(evidence, name, value):
    (evidence / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def prepare(root, evidence, home):
    for name in ['app.py', 'config.env']:
        (root / name).unlink(missing_ok=True)
    (root / 'owned.rs').write_text('// Owned inert report fixture. Never executed.\n')
    config = home / '.kuzushi/v3/config.toml'
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model="openai-codex:gpt-5.5"\n[runtime]\nthinking_level="medium"\n')
    (evidence / 'report-path.txt').write_text('.kuzushi/reports/owned-界.json')
    save(evidence, 'state', {'home':str(home),'sourceHash':hashlib.sha256((root/'owned.rs').read_bytes()).hexdigest(),
        'configHash':hashlib.sha256(config.read_bytes()).hexdigest()})


def preference(root, evidence):
    state = json.loads((evidence / 'state.json').read_text())
    files = list((Path(state['home']) / '.kuzushi/v3/report-choices').glob('*.json'))
    assert len(files) == 1
    value = json.loads(files[0].read_text())
    assert value['schemaVersion'] == 1 and Path(value['target']).resolve() == root
    assert value['format'] == 'json' and value['completeness'] == 'open'
    assert value['destinations']['json'] == '.kuzushi/reports/owned-界.json'
    assert set(value) == {'schemaVersion','target','format','completeness','destinations','provenanceDetails'}
    return files[0], value


def check(root, evidence, stage):
    state = json.loads((evidence / 'state.json').read_text())
    assert hashlib.sha256((root/'owned.rs').read_bytes()).hexdigest() == state['sourceHash']
    config = Path(state['home']) / '.kuzushi/v3/config.toml'
    assert hashlib.sha256(config.read_bytes()).hexdigest() == state['configHash']
    path, choices = preference(root, evidence)
    database = root / '.kuzushi/v3/index.sqlite3'
    if database.exists():
        with sqlite3.connect(database.as_uri()+'?mode=ro', uri=True) as db:
            tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            for table in ['finding_observations','review_decisions','investigation_call_reservations','investigation_work_attempts']:
                if table in tables:
                    assert db.execute('select count(*) from '+table).fetchone()[0] == 0, table
    assert not (root / '.kuzushi/v3/campaigns').exists()
    export = root / '.kuzushi/reports/owned-界.json'
    if stage in ['exported', 'repaired']:
        assert export.exists()
        value = json.loads(export.read_text())
        assert value == [] or (isinstance(value, dict) and not value.get('findings'))
    else:
        assert not export.exists(), 'Choice persistence must not export automatically.'
    save(evidence, stage+'-check', {'preferencesFile':str(path),'choices':choices,
        'providerRequests':0,'scannerJobs':0,'sourceExecuted':False,'configurationUnchanged':True,
        'ownedSourceUnchanged':True,'exportExists':export.exists(),'noApprovalFields':True})


def damage(root, evidence):
    path, _ = preference(root, evidence)
    path.write_text('{OWNED_DAMAGED_REPORT_CHOICES')
    save(evidence, 'damaged-state', {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})


def damaged_export(root, evidence):
    damaged = json.loads((evidence/'damaged-state.json').read_text())
    assert hashlib.sha256(Path(damaged['path']).read_bytes()).hexdigest() == damaged['sha256']
    export = root / '.kuzushi/reports/owned-界.json'
    assert export.exists()
    value = json.loads(export.read_text())
    assert value['format'] == 'kuzushi.workspace.findings.v2' and value['count'] == 0 and value['findings'] == []
    save(evidence, 'damaged-export-check', {'damagedPreferencesUnchanged':True,
        'explicitExportExists':True,'providerRequests':0,'scannerJobs':0,'sourceExecuted':False})


root, evidence = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
action = sys.argv[3]
if action == 'prepare':
    prepare(root, evidence, Path(sys.argv[4]).resolve())
elif action == 'damage':
    damage(root, evidence)
elif action == 'damaged-export':
    damaged_export(root, evidence)
else:
    check(root, evidence, action)
