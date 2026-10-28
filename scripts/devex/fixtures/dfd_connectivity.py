"""Owned recorded topology; no model request, target execution or automatic repair."""
import hashlib,json,sqlite3,sys
from pathlib import Path
from context_diagram import document

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(folder,name,value):(folder/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
def state(root):
 manifest=root/'.kuzushi/threat-models/manifest.json'
 objects=root/'.kuzushi/threat-models/objects'
 captured={str(p.relative_to(objects)):sha(p) for p in objects.rglob('*') if p.is_file()}
 assert captured,'Expected immutable context objects'
 return {'manifestSha256':sha(manifest),'active':json.loads(manifest.read_text())['active'],'objects':captured}
def seed(root,evidence):
 for name in ['app.py','config.env']:(root/name).unlink(missing_ok=True)
 (root/'reader.py').write_text('# Owned diagram source, never executed.\n')
 value=document('Owned')
 value['systemContext']='A labeled topology fixture has three connected components and two source definitions awaiting role review. No runtime behavior is established.'
 for key,label in [('invoice-type','Invoice definition'),('principal-type','Principal definition')]:
  value['dfd']['nodes'].append({'id':key,'name':label,'type':'process','trustZone':'application','description':'Source definition.\nRuntime role needs operator review.','purpose':'Labeled metadata for diagram inspection.','sourceRefs':['reader.py:1']})
 (root/'ctx.json').write_text(json.dumps(value))
 save(evidence,'source-before',{p.name:sha(p) for p in root.iterdir() if p.is_file() and not p.name.startswith('.')})
def verify(root,evidence,stage):
 if stage=='paged':
  captures='\n'.join(p.read_text() for p in evidence.glob('*-40x12.txt'))
  assert 'No incoming' in captures,'The selected component flow notice was not reached with paging'
 for name,digest in json.loads((evidence/'source-before.json').read_text()).items():assert sha(root/name)==digest,name
 value=json.loads((root/'ctx.json').read_text());assert len(value['dfd']['nodes'])==5 and len(value['dfd']['flows'])==2
 current=state(root)
 if stage=='accepted':save(evidence,'accepted-context',current)
 else:assert current==json.loads((evidence/'accepted-context.json').read_text())
 assert not list((root/'.kuzushi/v3/campaigns').glob('*/plan.json'))
 counts={}
 index=root/'.kuzushi/v3/index.sqlite3'
 if index.exists():
  with sqlite3.connect(index.as_uri()+'?mode=ro',uri=True) as db:
   tables={r[0] for r in db.execute("select name from sqlite_master where type='table'")}
   for table in ['investigation_work_attempts','investigation_call_reservations','finding_observations','review_decisions']:
    counts[table]=db.execute('select count(*) from '+table).fetchone()[0] if table in tables else 0
 assert all(v==0 for v in counts.values()),counts
 save(evidence,stage+'-check',{'sourceUnchanged':True,'contextUnchanged':stage!='accepted','rawNodes':5,'rawFlows':2,'newFlows':0,'savedPlans':0,'ledgerCounts':counts,'liveProviderRequests':0,'targetSourceExecuted':False,'fixture':'Owned labeled topology; manually declared context, no runtime architecture or finding proof.'})
if __name__=='__main__':
 root,evidence=[Path(v).resolve() for v in sys.argv[1:3]];action=sys.argv[3]
 if action=='seed':seed(root,evidence)
 else:verify(root,evidence,action)
