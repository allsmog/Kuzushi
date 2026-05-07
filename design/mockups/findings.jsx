// Findings view — DEFENSE module. Browse / filter persisted findings.
// Table-of-findings + filter chips + selection cursor.

function FindingsView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function chip(label, n, on) {
    return [
      [' ', null],
      [on ? '[' : ' ', on ? 'c-accent' : 'c-subtle'],
      [(label + ' '.repeat(20)).slice(0, label.length), on ? 'c-accent' : 'c-muted'],
      [':' + n, on ? 'c-accent' : 'c-muted'],
      [on ? ']' : ' ', on ? 'c-accent' : 'c-subtle'],
    ];
  }

  function findingRow(focused, alias, sev, status, age, name, where) {
    const sevMap = { critical: 'c-sev-critical', high: 'c-sev-high', medium: 'c-sev-medium', low: 'c-sev-low' };
    const statusMap = {
      'open':       'c-warn',
      'verified':   'c-danger',
      'patched':    'c-success',
      'suppressed': 'c-subtle',
      'wontfix':    'c-subtle',
    };
    if (focused) {
      const text = ' ' + alias + '  '
        + (sev.toUpperCase() + ' '.repeat(10)).slice(0, 9)
        + (status + ' '.repeat(12)).slice(0, 11)
        + (age + ' '.repeat(8)).slice(0, 6)
        + (name + ' '.repeat(60)).slice(0, 46)
        + ' ' + where + ' ';
      return (
        <span className="row" key={alias}>
          <span className="c-accent">{'  ▌'}</span>
          <span className="c-sel">{text}</span>
        </span>
      );
    }
    return [
      ['    ', null],
      [(alias + ' '.repeat(8)).slice(0, 7), 'c-accent'],
      ['  ', null],
      [(sev.toUpperCase() + ' '.repeat(10)).slice(0, 9), sevMap[sev]],
      [(status + ' '.repeat(12)).slice(0, 11), statusMap[status] || 'c-muted'],
      [(age + ' '.repeat(8)).slice(0, 6), 'c-muted'],
      [(name + ' '.repeat(60)).slice(0, 46), 'c-primary'],
      [where, 'c-muted'],
    ];
  }

  // filter row — the chips
  const filterRow = window.row([
    [' ', null],
    ['filter ', 'c-muted'],
    ...chip('sev', '5+', true),
    ...chip('status', 'open', true),
    ...chip('age', 'all', false),
    ...chip('module', 'any', false),
    ...chip('owner', 'me', false),
    ['   ', null],
    [' /', 'c-muted'], ['orders', 'c-primary'],
    ['   ', null],
    ['→ ', 'c-subtle'], ['11', 'c-primary'], [' of ', 'c-muted'], ['38', 'c-primary'], [' findings', 'c-muted'],
  ], W, 'flt');

  const heads = window.row([
    ['    ', null],
    [('alias' + ' '.repeat(7)).slice(0, 7), 'c-label'],
    ['  ', null],
    [('sev' + ' '.repeat(9)).slice(0, 9), 'c-label'],
    [('status' + ' '.repeat(11)).slice(0, 11), 'c-label'],
    [('age' + ' '.repeat(6)).slice(0, 6), 'c-label'],
    [('finding' + ' '.repeat(46)).slice(0, 46), 'c-label'],
    ['location', 'c-label'],
  ], W, 'heads');

  // Wrap segment-arrays via window.row; pass JSX (focused row) straight through.
  const wrap = (val, key) => Array.isArray(val) ? window.row(val, W, key) : val;

  const rows = [
    wrap(findingRow(false, 'F-0001', 'critical', 'verified',  '6h',  'sql injection via order_id concatenation',     'apps/api/orders.rs:142'), 'r1'),
    wrap(findingRow(true,  'F-0002', 'critical', 'verified',  '6h',  'prompt-injection sink — model reads body',     'apps/web/agents/concierge.ts:88'), 'r2'),
    wrap(findingRow(false, 'F-0012', 'critical', 'open',      '12m', 'prompt-injection in refund-bot',                'apps/web/agents/refund-bot.ts:127'), 'r3'),
    wrap(findingRow(false, 'F-0003', 'high',     'patched',   '4d',  'jwt verify with alg=none accepted',            'apps/api/auth/jwt.rs:54'), 'r4'),
    wrap(findingRow(false, 'F-0004', 'high',     'open',      '6h',  'shell exec from cron payload',                 'jobs/worker.py:213'), 'r5'),
    wrap(findingRow(false, 'F-0005', 'high',     'open',      '6h',  'path traversal in /assets/<file>',             'apps/web/server.ts:301'), 'r6'),
    wrap(findingRow(false, 'F-0013', 'high',     'open',      '11m', 'second-order injection · order.notes',         'apps/web/agents/concierge.ts:241'), 'r7'),
    wrap(findingRow(false, 'F-0006', 'medium',   'open',      '6h',  'open redirect on /login?next=',                'apps/web/server.ts:78'), 'r8'),
    wrap(findingRow(false, 'F-0007', 'medium',   'patched',   '2d',  'csrf token not bound to session',              'apps/web/middleware.ts:44'), 'r9'),
    wrap(findingRow(false, 'F-0008', 'medium',   'open',      '6h',  'unbounded regex on /search',                   'apps/api/search.rs:31'), 'r10'),
    wrap(findingRow(false, 'F-0009', 'low',      'suppressed','1d',  'cors allows null origin',                       'apps/api/cors.rs:12'), 'r11'),
  ];

  // selected detail — preview pane
  const detail = [
    window.sectionHeader('F-0002 · DETAIL', W, 'sec-d'),
    window.row([T('   '), m('first seen   '), p('2026-05-06 08:11'), m('  ·  '), m('module '), p('agentic-sast'), m('  ·  '), m('confidence '), p('0.93')], W, 'd1'),
    window.row([T('   '), m('verified by  '), p('avi.k'), m(' at '), p('14:55'), m('  ·  PoC: '), p('.kuzushi/runs/…/poc-h2.txt')], W, 'd2'),
    window.row([T('   '), m('owner        '), p('@web-platform'), m('  ·  '), m('SLA '), p('3d'), m('  ·  '), m('breaches in '), [' 56h ', 'c-warn']], W, 'd3'),
    window.row([T('   '), m('summary      '), p('user-controlled review.body splices into the concierge agent\'s system prompt')], W, 'd4'),
    window.row([T('   '), m('next         '), a('/use patch F-0002'), m('  ·  '), a('/use verify F-0002 --rerun'), m('  ·  '), a('/show trace')], W, 'd5'),
  ];

  const lines = [
    window.logLine('in', '14:38:01', [m(' /use '), a('findings')], W, 'l1'),
    window.logLine('in', '14:38:09', [m(' /findings '), a('--severity high+ --status open,verified /orders')], W, 'l2'),
    window.blankRow(W, 'b1'),
    filterRow,
    window.blankRow(W, 'b2'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'rule'),
    ...rows,
    window.blankRow(W, 'b3'),
    ...detail,
  ];

  return (
    <window.TermFrame title="kuzushi · findings · browse / filter">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'findings', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'findings · 11 of 38 shown', findings: 38,
        promptModule: 'findings',
        keybinds: [
          ['j/k', 'row'], ['enter', 'open'],
          ['v', 'verify'], ['p', 'patch'],
          ['s', 'suppress'], ['/', 'filter'],
        ],
      })}
    </window.TermFrame>
  );
}

window.FindingsView = FindingsView;
