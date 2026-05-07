// triage queue · empty / cleared

function TriageQueueView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function r(state, id, sev, name, where, who, mins) {
    const sMap = {
      pending:[' · ', 'c-subtle'],
      done:   [' ✓ ', 'c-success'],
      working:[' ⏵ ', 'c-warn'],
      stale:  [' ! ', 'c-warn'],
    };
    const sevMap = { critical:'c-sev-critical', high:'c-sev-high', medium:'c-sev-medium', low:'c-sev-low' };
    const idCell = (id + ' '.repeat(10)).slice(0, 8);
    const sCell  = (sev.toUpperCase() + ' '.repeat(10)).slice(0, 9);
    const nCell  = (name + ' '.repeat(60)).slice(0, 36);
    const wCell  = (where + ' '.repeat(40)).slice(0, 30);
    const aCell  = (who + ' '.repeat(10)).slice(0, 8);
    const mCell  = (mins + ' '.repeat(8)).slice(0, 6);
    return [
      [' ', null], sMap[state],
      [idCell, 'c-accent'],
      [sCell, sevMap[sev]],
      [nCell, 'c-primary'],
      [wCell, 'c-muted'],
      [aCell, 'c-muted'],
      [mCell, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in','15:20:01',[m(' /triage queue')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('queue '), p('11 of 38'),  m('   working '), p('1'),
      m('   pending '), p('7'),  m('   done '), p('3'),  m('   stale '), p('0')], W, 'h0'),
    window.row([T('  '), m('actor '), p('triager · openai:gpt-4.1-mini'),
      m('   throughput '), p('22 / hr'), m('   est clear in '), p('~ 18 min')], W, 'h1'),
    window.blankRow(W, 'b2'),
    window.row([
      [' ', null], ['   ', null],
      [('id' + ' '.repeat(8)).slice(0, 8), 'c-label'],
      [('sev' + ' '.repeat(9)).slice(0, 9), 'c-label'],
      [('name' + ' '.repeat(36)).slice(0, 36), 'c-label'],
      [('where' + ' '.repeat(30)).slice(0, 30), 'c-label'],
      [('who' + ' '.repeat(8)).slice(0, 8), 'c-label'],
      ['mins', 'c-label'],
    ], W, 'h'),
    window.row([[' ', null], ['─'.repeat(W - 2), 'c-subtle']], W, 'r'),
    window.row(r('done',    'F-0001', 'critical', 'sql injection · order_id concat',           'apps/api/orders.rs:142',     'jen.t', '2'),  W, 't1'),
    window.row(r('working', 'F-0002', 'critical', 'prompt-injection (concierge)',              'concierge.ts:88',             'jen.t', '0'),  W, 't2'),
    window.row(r('done',    'F-0003', 'high',     'jwt verify with alg=none',                  'jwt.rs:54',                   'avi.k', '14'), W, 't3'),
    window.row(r('pending', 'F-0004', 'high',     'shell exec from cron payload',              'jobs/worker.py:213',          '—',     '—'),  W, 't4'),
    window.row(r('pending', 'F-0005', 'high',     'path traversal in /assets',                  'apps/web/server.ts:301',     '—',     '—'),  W, 't5'),
    window.row(r('pending', 'F-0012', 'critical', 'prompt-injection (refund-bot $-loss)',      'refund-bot.ts:127',           '—',     '—'),  W, 't6'),
    window.row(r('pending', 'F-0019', 'high',     'taint review.body → exec sink',             'concierge.ts:142',            '—',     '—'),  W, 't7'),
    window.row(r('pending', 'F-0023', 'high',     'IDOR on /api/order/<other-tenant>',          'orders.rs:88',               '—',     '—'),  W, 't8'),
    window.row(r('pending', 'F-0027', 'high',     'cross-lang taint py→ts (redis)',             'jobs/worker.py:184',         '—',     '—'),  W, 't9'),
    window.row(r('pending', 'F-0031', 'high',     'oauth state not bound to session',           'apps/web/oauth.ts:61',       '—',     '—'),  W, 't10'),
    window.row(r('done',    'F-0034', 'high',     'k8s deploy as root',                         'infra/k8s/api.yaml:14',      'mira.l','22'), W, 't11'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('AUTOPILOT', W, 's1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  triage classifies severity-floor '),
      p('high+'), m(' automatically · '), p('medium'), m(' and below stay pending until you ask')], W, 'a1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  defender critic re-runs after '),
      p('triager'), m(' votes critical (refusal rate '), p('4%'), m(')')], W, 'a2'),
    window.row([T('   '), [' · ', 'c-subtle'], m('  no auto-promote without operator approval — even on F-0012')], W, 'a3'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','15:20:01',[m(' '), a('a'),  m(' assign @me · '), a('s'), m(' status · '),
      a('/triage pause'), m(' · '), a('/triage resume')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /triage queue">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'triage', cost: '$0.61' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'triage · 1 working · 7 pending · 22/hr', findings: 38,
        promptModule: 'triage',
        keybinds: [['j/k','row'],['a','assign'],['s','status'],['/triage pause','halt']],
      })}
    </window.TermFrame>
  );
}
window.TriageQueueView = TriageQueueView;
