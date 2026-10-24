"""One intercepted malformed architecture response, never repaired or accepted."""
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path

import dfd_context
from context_comparison import run_tool
from investigation_journey import wait_jobs

CAMPAIGN = 'invalid-node-role'
INVESTIGATION = 'invalid-node-role-accounting'


def save(evidence, name, value):
    (evidence / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def prepare(root, evidence, home):
    # Host-side journey setup does not inherit the later TUI env directive.
    # Prepare and execute under the same isolated operator configuration.
    os.environ['HOME'] = str(home)
    for key in ('NODE_OPTIONS', 'KUZUSHI_LANGGRAPH_BRIDGE', 'KUZUSHI_MODEL', 'KUZUSHI_V2_MODEL',
                'KUZUSHI_API_KEY_ENV', 'KUZUSHI_V2_API_KEY_ENV', 'KUZUSHI_BASE_URL', 'KUZUSHI_V2_BASE_URL',
                'KUZUSHI_ANTHROPIC_OAUTH', 'KUZUSHI_ANTHROPIC_OAUTH_CREDENTIALS'):
        os.environ.pop(key, None)
    dfd_context.prepare(root, evidence, home)
    binary = os.environ['KUZUSHI_NATIVE_BIN']
    active = run_tool(binary, root, evidence, 'active-original', 'threat-model:import',
                      {'path': str(root / '.kuzushi/manual-context.json'), 'label': 'Original active context', 'activate': True})['data']['modelRef']
    selected = json.loads((evidence / 'dfd-context-before.json').read_text())['selected']
    provider = evidence / 'provider.mjs'
    original = provider.read_text()
    assert original.count('type: "process"') == 1
    provider.write_text(original.replace('type: "process"', 'type: "data-type"'))
    planned = run_tool(binary, root, evidence, 'role-plan', 'campaign:context-study', {
        'campaignId': CAMPAIGN, 'investigationId': INVESTIGATION,
        'contextInput': {'sourcePaths': dfd_context.SELECTED, 'inheritedContextRef': selected,
                         'saveRejectedOutput': True, 'maxSourceBytes': 8192, 'maxOutputTokens': 1024}})['data']
    run_tool(binary, root, evidence, 'role-approval', 'campaign:approve-allowance', {
        'investigationId': INVESTIGATION, 'expectedRevision': 0, 'model': planned['model'],
        'maxProviderCalls': 2, 'protectedReviewCalls': 1, 'reason': 'Owned offline one-response node-role rejection',
        'campaignId': CAMPAIGN, 'campaignPlanSha256': planned['planSha256'], 'campaignJobs': 1, 'maxJobAttempts': 1})
    (evidence / 'context-command.txt').write_text('campaign ' + CAMPAIGN)
    manifest = root / '.kuzushi/threat-models/manifest.json'
    save(evidence, 'role-before', {'active': active, 'selected': selected, 'sources': dfd_context.hashes(root),
         'manifestSha256': hashlib.sha256(manifest.read_bytes()).hexdigest(), 'planSha256': planned['planSha256']})


def verify(root, evidence):
    before = json.loads((evidence / 'role-before.json').read_text())
    campaign = root / '.kuzushi/v3/campaigns' / CAMPAIGN
    plan = json.loads((campaign / 'plan.json').read_text())
    jobs = wait_jobs(root, plan, {'failed'})
    assert len(jobs) == len(plan['jobs']) == 1 and plan['workers'] == 1
    job = next(iter(jobs.values()))
    assert job['attempts'] == job['dispatches'] == 1
    run = root / '.kuzushi/v3/runs' / job['runId']
    raw = (run / 'rejected-context-output.txt').read_text()
    assert 'data-type' in raw and 'Draft evidence reader' in raw
    assert len(raw.encode()) < 17 * 1024
    assert len((evidence / 'dfd-context-calls.jsonl').read_text().splitlines()) == 1
    manifest = root / '.kuzushi/threat-models/manifest.json'
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == before['manifestSha256']
    assert json.loads(manifest.read_text())['active'] == before['active']
    assert dfd_context.hashes(root) == before['sources']
    assert len(list((root / '.kuzushi/v3/campaigns').glob('*/plan.json'))) == 1
    with sqlite3.connect((root / '.kuzushi/v3/index.sqlite3').as_uri() + '?mode=ro', uri=True) as db:
        assert db.execute('select count(*) from investigation_call_reservations').fetchone()[0] == 1
        assert db.execute('select count(*) from investigation_call_reservations where settled_at is null or review=1').fetchone()[0] == 0
        assert db.execute('select count(*) from investigation_work_attempts').fetchone()[0] == 1
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        if 'finding_observations' in tables:
            assert db.execute('select count(*) from finding_observations').fetchone()[0] == 0
    save(evidence, 'role-verified', {'attempts': 1, 'interceptedRequests': 1, 'newModelRequests': 0,
         'repairRequests': 0, 'contextAccepted': False, 'activeUnchanged': True, 'sourceUnchanged': True,
         'providerDollarCost': 'unknown', 'fixedJobs': 1})


if __name__ == '__main__':
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    if sys.argv[3] == 'seed':
        prepare(root, evidence, Path(sys.argv[4]).resolve())
    else:
        verify(root, evidence)
