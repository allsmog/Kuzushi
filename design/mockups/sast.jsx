// SAST view — umbrella sast:scan with progress per task and findings table.

function SastView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  // Progress bar helper — returns a styled segment list
  function bar(label, done, total, status, color = 'c-success') {
    const width = 24;
    const pct = total === 0 ? 0 : done / total;
    const filled = Math.round(width * pct);
    const empty  = width - filled;
    return [
      [(label + ' '.repeat(20)).slice(0, 20), 'c-primary'],
      [' [', 'c-subtle'],
      ['█'.repeat(filled), color],
      ['░'.repeat(empty), 'c-subtle'],
      ['] ', 'c-subtle'],
      [(`${done}/${total}`).padStart(7), 'c-muted'],
      ['  ', null],
      [status, color === 'c-warn' ? 'c-warn' : color === 'c-danger' ? 'c-danger' : 'c-success'],
    ];
  }

  // Finding row: [alias, severity, name, file:line]
  function finding(alias, sev, name, where) {
    const sevMap = {
      critical: 'c-sev-critical', high: 'c-sev-high',
      medium: 'c-sev-medium', low: 'c-sev-low',
    };
    return [
      [' ', null],
      [alias, 'c-accent'],
      ['  ', null],
      [(sev.toUpperCase() + ' '.repeat(10)).slice(0, 9), sevMap[sev]],
      [(name + ' '.repeat(60)).slice(0, 50), 'c-primary'],
      [where, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in', '14:31:55', [m(' /scan · plan confirmed')], W, 'l1'),
    window.logLine('run', '14:31:55', [m(' sast:scan · tasks '), a('semgrep, secret-scan, agentic-sast'), m(' · triage on')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('semgrep             ', 612, 612, 'done · 18 raw hits',     'c-success')], W, 'p1'),
    window.row([T('   '), ...bar('secret-scan         ', 1284, 1284, 'done · 0 hits',         'c-success')], W, 'p2'),
    window.row([T('   '), ...bar('agentic-sast        ',  87,  120, 'tracing dataflows…',     'c-warn')], W, 'p3'),
    window.row([T('   '), ...bar('triage (post-scan)  ',  11,  18, 'classifying…',            'c-warn')], W, 'p4'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('FINDINGS · 11 triaged · 7 pending', W, 'sec1'),
    window.row(finding('F-0001', 'critical', 'sql injection via order_id concatenation',     'apps/api/orders.rs:142'), W, 'f1'),
    window.row(finding('F-0002', 'critical', 'prompt-injection sink — model reads user body','apps/web/agents/concierge.ts:88'), W, 'f2'),
    window.row(finding('F-0003', 'high',     'jwt verify with alg=none accepted',            'apps/api/auth/jwt.rs:54'), W, 'f3'),
    window.row(finding('F-0004', 'high',     'shell exec from cron payload',                 'jobs/worker.py:213'), W, 'f4'),
    window.row(finding('F-0005', 'high',     'path traversal in /assets/<file>',             'apps/web/server.ts:301'), W, 'f5'),
    window.row(finding('F-0006', 'medium',   'open redirect on /login?next=',                'apps/web/server.ts:78'), W, 'f6'),
    window.row(finding('F-0007', 'medium',   'csrf token not bound to session',              'apps/web/middleware.ts:44'), W, 'f7'),
    window.row(finding('F-0008', 'medium',   'unbounded regex on /search (catastrophic)',    'apps/api/search.rs:31'), W, 'f8'),
    window.row(finding('F-0009', 'low',      'cors allows null origin',                      'apps/api/cors.rs:12'), W, 'f9'),
    window.row(finding('F-0010', 'low',      'cookie set without SameSite',                  'apps/web/session.ts:60'), W, 'f10'),
    window.row(finding('F-0011', 'low',      'console.log of req.body in handler',           'apps/web/server.ts:415'), W, 'f11'),
    window.row([T('   '), m('   … '), p('7 more pending triage'), m(' · '), a('/findings --severity high'), m(' to drill in')], W, 'fmore'),
    window.blankRow(W, 'b3'),
    window.logLine('agent', '14:33:42', [
      [' two CRITICALs share a sink — ', 'c-primary'],
      ['F-0001', 'c-accent'], [' and ', 'c-primary'], ['F-0002', 'c-accent'],
      [' both end at ', 'c-primary'], ['orders.rs:142', 'c-warn'], ['.', 'c-primary'],
    ], W, 'l3'),
    window.logLine('flow', '14:33:42', [
      m(' recommend '), a('/use verify F-0001'), m(' first'),
    ], W, 'l3b'),
  ];

  return (
    <window.TermFrame title="kuzushi · sast:scan · umbrella run">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'sast', cost: '$0.41' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end-1')}
      {window.footer({
        stage: 'sast:scan · agentic 73% · triage 61%', findings: 11,
        promptModule: 'sast',
        keybinds: [
          ['/findings', 'browse'], ['/open', 'F-0001'],
          ['/use', 'verify | triage'], ['/pause', 'halt scan'],
        ],
      })}
    </window.TermFrame>
  );
}

window.SastView = SastView;
