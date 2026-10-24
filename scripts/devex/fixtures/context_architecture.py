"""Owned architecture-correction UI fixture. No inference or target execution."""
import hashlib
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

from context_comparison import run_tool
from context_diagram import document
from context_edit import object_path


def save(evidence, name, value):
    (evidence / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources(root):
    return {name: sha(root / name) for name in ['reader.py', 'app.py', 'config.env'] if (root / name).exists()}


def seed(root, evidence, home):
    assert root == evidence / 'fixture-target'
    os.environ['HOME'] = str(home)
    config = home / '.kuzushi/v3/config.toml'
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model="openai-codex:gpt-5.5"\n[runtime]\nthinking_level="medium"\n')
    (root / 'reader.py').write_text('# Owned inert architecture fixture. Never executed.\n')
    references = {}
    for key, label in [('selected', 'Alpha'), ('active', 'Beta')]:
        value = document(label)
        value['dfd']['nodes'][0]['type'] = 'process'
        value['dfd']['flows'][0]['sourceId'] = 'api'
        value['openQuestions'] = ['Who owns the input?']
        value['provenance'] = {'fixture': 'Labeled architecture with an intentionally incorrect caller role and endpoint.'}
        result = run_tool(os.environ['KUZUSHI_NATIVE_BIN'], root, evidence, 'import-' + key,
                          'threat-model:import', {'document': value, 'label': label, 'activate': True})
        references[key] = result['data']['modelRef']
    manifest = json.loads((root / '.kuzushi/threat-models/manifest.json').read_text())
    save(evidence, 'architecture-before', {'home': str(home), 'references': references, 'manifest': manifest,
         'sources': sources(root), 'mirrorHash': sha(root / '.kuzushi/threat-model.json'),
         'objects': {key: sha(object_path(root, ref)) for key, ref in references.items()},
         'configHash': sha(config)})
    (evidence / 'choice-paste.txt').write_text('process\nscan batch\n')
    (evidence / 'single-line-paste.txt').write_text('Bad\nname')
    (evidence / 'caller-name.txt').write_text('Reviewed caller')


def verify(root, evidence, stage):
    before = json.loads((evidence / 'architecture-before.json').read_text())
    os.environ['HOME'] = before['home']
    assert sources(root) == before['sources']
    assert sha(Path(before['home']) / '.kuzushi/v3/config.toml') == before['configHash']
    manifest = json.loads((root / '.kuzushi/threat-models/manifest.json').read_text())
    assert manifest['active'] == before['references']['active']
    assert manifest['models'][:2] == before['manifest']['models']
    assert sha(root / '.kuzushi/threat-model.json') == before['mirrorHash']
    for key, reference in before['references'].items():
        assert sha(object_path(root, reference)) == before['objects'][key]
    database = root / '.kuzushi/v3/index.sqlite3'
    if database.exists():
        with sqlite3.connect(database.as_uri() + '?mode=rw', uri=True) as db:
            db.execute('PRAGMA query_only=ON')
            tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            for table in ['investigation_work_attempts', 'investigation_call_reservations', 'finding_observations', 'review_decisions']:
                if table in tables:
                    assert db.execute('select count(*) from ' + table).fetchone()[0] == 0, table
    plans = list((root / '.kuzushi/v3/campaigns').glob('*/plan.json'))
    if stage == 'draft':
        assert manifest == before['manifest'] and not plans
        save(evidence, 'architecture-draft-verified', {'sourceUnchanged': True, 'copiesPublished': 0, 'jobs': 0, 'providerCalls': 0})
        return
    assert len(manifest['models']) == 3
    model = manifest['models'][2]
    assert len(model['revisions']) == 1
    revision = model['revisions'][0]
    reference = {'modelId': model['modelId'], 'revisionId': revision['revisionId'], 'sha256': revision['sha256']}
    value = json.loads(object_path(root, reference).read_text())
    original = json.loads(object_path(root, before['references']['selected']).read_text())
    assert value['dfd']['nodes'][0]['name'] == 'Reviewed caller'
    assert value['dfd']['nodes'][0]['type'] == 'external-entity'
    assert value['dfd']['flows'][0]['sourceId'] == 'client'
    assert value['dfd']['nodes'][0]['id'] == original['dfd']['nodes'][0]['id']
    assert value['attackSurface'] == original['attackSurface']
    assert value['dfd']['trustBoundaries'] == original['dfd']['trustBoundaries']
    assert value['userEdited'] and 'verification' not in value
    assert value['provenance']['operatorEdit']['sourceModelRef'] == before['references']['selected']
    assert set(value['provenance']['operatorEdit']['fields']) == {'/dfd/nodes/0/name', '/dfd/nodes/0/type', '/dfd/flows/0/sourceId'}
    assert revision['source'] == 'operator-edit' and revision['sourceRevisionId'] == before['references']['selected']['revisionId']
    if stage == 'saved':
        assert not plans
    else:
        assert len(plans) == 1
        plan = json.loads(plans[0].read_text())
        assert plan['baseInput']['threatModelRef'] == reference
        assert plan['baseInput']['tasks'] == ['secret-scan'] and plan['trialsPlanned'] == 3
        (evidence / 'resume-command.txt').write_text('campaign ' + plan['campaignId'])
    if stage == 'resumed':
        ansi = next(evidence.glob('*-recovered-architecture.ansi')).read_text()
        for sgr in re.findall(r'\x1b\[([\d;]*)m', ansi):
            assert not any(30 <= int(code) <= 38 or 40 <= int(code) <= 48 or 90 <= int(code) <= 107 for code in sgr.split(';') if code)
    save(evidence, 'architecture-' + stage + '-verified', {'copyRef': reference, 'sourceUnchanged': True,
         'activeUnchanged': True, 'originalObjectsUnchanged': True, 'copiesPublished': 1, 'providerCalls': 0,
         'findingDecisions': 0, 'plannedJobs': 0 if stage == 'saved' else 3, 'jobsStarted': 0, 'sourceExecuted': False})


if __name__ == '__main__':
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == 'seed':
        seed(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence, sys.argv[3])
