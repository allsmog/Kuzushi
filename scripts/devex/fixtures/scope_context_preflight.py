"""Inspect the prepared owned monorepo plan without granting or launching work."""
import hashlib,json,sqlite3,sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[3]
FIXTURE=REPO/'scripts/devex/artifacts/monorepo-scope-live-20261025/attempt-2'

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def verify(root,evidence,stage):
    assert root==FIXTURE/'target'
    control=FIXTURE/'control'
    prepared=json.loads((control/'prepared.json').read_text())
    source=json.loads((control/'source-before.json').read_text())
    assert len(source)==602 and all(digest(root/name)==sha for name,sha in source.items())
    state=root/'.kuzushi/v3'
    plan=state/'campaigns'/prepared['campaign']/'plan.json'
    document=json.loads(plan.read_text())
    assert len(document['jobs'])==1 and document['workers']==1
    assert document['jobs'][0]['tool']=='pack:suggest-scopes'
    assert document['jobs'][0]['input']['threatModelRef']==prepared['contextRef']
    assert document['jobs'][0]['input']['thinkingLevel']=='low'
    assert not list((state/'campaigns').glob('*/queue.json'))
    manifest=root/'.kuzushi/threat-models/manifest.json'
    assert json.loads(manifest.read_text()).get('active') is None
    baseline={'plan':digest(plan),'contextManifest':digest(manifest),'operatorConfig':digest(FIXTURE/'operator-home/.kuzushi/v3/config.toml')}
    before=evidence/'monorepo-plan-before.json'
    if stage=='inspect':
        assert not before.exists();before.write_text(json.dumps(baseline,indent=2)+'\n')
    else:assert baseline==json.loads(before.read_text())
    assert not (evidence/'denied-fetch.jsonl').exists(),'Unexpected fetch was blocked'
    with sqlite3.connect((state/'index.sqlite3').as_uri()+'?mode=ro',uri=True) as db:
        tables={row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        counts={name:db.execute('select count(*) from '+name).fetchone()[0]
            for name in tables if name.startswith('investigation_')}
        assert all(value==0 for value in counts.values()),counts
        assert db.execute('select count(*) from finding_observations').fetchone()[0]==0
    for record in (state/'runs').glob('*/run.json'):
        assert not json.loads(record.read_text()).get('llmCalls'),record
    (evidence/(stage+'-check.json')).write_text(json.dumps({'sourceFilesUnchanged':602,
        'contextActive':False,'queueExists':False,'providerRequestsRecorded':0,
        'networkFetchAttempts':0,'targetSourceExecuted':False,'planUnchanged':True,
        'investigationTableCounts':counts},indent=2)+'\n')

if __name__=='__main__':
    root,evidence,stage=sys.argv[1:];verify(Path(root).resolve(),Path(evidence).resolve(),stage)
