"""Compare two labeled saved architectures through runtime-free prepared dispatch."""
import copy
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path

from context_comparison import run_tool
from context_diagram import document
from investigation_journey import seed, source_hashes


def save(evidence, name, value):
    (evidence / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def prepare(root, evidence, home):
    seed(root, evidence, home)
    (root / 'reader.py').write_text('# Owned architecture evidence. Never executed.\n')
    parent = document('Baseline')
    parent['provenance'] = {'gitRevision': '1' * 40, 'treeHash': 'baseline-labeled-claim', 'revisionDirty': True}
    parent['systemContext'] = 'Labeled saved baseline architecture. Source identities are fixture claims, not checkout checks.'
    before = run_tool(os.environ['KUZUSHI_NATIVE_BIN'], root, evidence, 'parent', 'threat-model:import',
                      {'document': parent, 'label': 'Baseline', 'activate': True})['data']['modelRef']
    candidate = copy.deepcopy(parent)
    candidate['systemContext'] = 'Labeled changed architecture. Reused IDs retain changed types, endpoints and evidence.'
    candidate['dfd']['nodes'][1]['type'] = 'data-store'
    candidate['dfd']['nodes'][1]['trustZone'] = 'restricted'
    candidate['dfd']['nodes'][1]['sourceRefs'] = [' reader.py:1']
    candidate['dfd']['flows'][1]['targetId'] = 'client'
    candidate['dfd']['trustBoundaries'][0]['innerZone'] = 'restricted'
    candidate['openQuestions'] = [{'id': 'ownership', 'question': 'Who owns this boundary?', 'answer': 'Needs operator review.'}]
    candidate['provenance'] = {'gitRevision': '2' * 40, 'treeHash': 'candidate-labeled-claim', 'revisionDirty': True,
                               'fileContext': {'receipt': {'inheritedContextRef': before, 'sourcePaths': ['reader.py'], 'sourcePartial': True}}}
    candidate['metadata'] = {'explicitUnknown': None}
    after = run_tool(os.environ['KUZUSHI_NATIVE_BIN'], root, evidence, 'candidate', 'threat-model:import',
                     {'document': candidate, 'label': 'Candidate', 'activate': False})['data']['modelRef']
    result = run_tool(os.environ['KUZUSHI_NATIVE_BIN'], root, evidence, 'shared-diff', 'threat-model:diff',
                      {'from': before['revisionId'], 'to': after['revisionId']})
    changes = result['data']['contextStructure']['changes']
    assert result['data']['contextStructure']['schemaVersion'] == 1
    assert any(row.get('identity') == 'api' and row['field'] == '/type' for row in changes)
    assert any(row.get('identity') == 'record' and row['field'] == '/targetId' for row in changes)
    manifest = root / '.kuzushi/threat-models/manifest.json'
    save(evidence, 'structure-before', {'parent': before, 'candidate': after, 'sources': source_hashes(root),
         'readerHash': hashlib.sha256((root / 'reader.py').read_bytes()).hexdigest(),
         'manifestHash': hashlib.sha256(manifest.read_bytes()).hexdigest(), 'liveRequests': 0,
         'sourceClaimsAreLabeledFixtureData': True})


def verify(root, evidence):
    before = json.loads((evidence / 'structure-before.json').read_text())
    assert source_hashes(root) == before['sources']
    assert hashlib.sha256((root / 'reader.py').read_bytes()).hexdigest() == before['readerHash']
    manifest = root / '.kuzushi/threat-models/manifest.json'
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == before['manifestHash']
    assert json.loads(manifest.read_text())['active'] == before['parent']
    assert not list((root / '.kuzushi/v3/campaigns').glob('*/plan.json'))
    assert not (evidence / 'investigation-calls.jsonl').exists()
    database = root / '.kuzushi/v3/index.sqlite3'
    if database.exists():
        with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
            tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
            for table in ['investigation_call_reservations', 'finding_observations', 'investigation_work_attempts']:
                if table in tables:
                    assert db.execute('select count(*) from ' + table).fetchone()[0] == 0
    save(evidence, 'structure-verified', {'sourceUnchanged': True, 'activeUnchanged': True, 'jobsCreated': 0,
         'liveRequests': 0, 'findingVerdicts': 0, 'comparisonSchemaVersion': 1})


if __name__ == '__main__':
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == 'seed':
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence)
