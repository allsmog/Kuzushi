// CodeQL view — query-pack run via codeql binary. Compile DB, run packs,
// emit SARIF. Slower than semgrep but deeper dataflow.

function CodeqlView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function bar(label, done, total, status, color = 'c-success') {
    const width = 24;
    const pct = total === 0 ? 0 : done / total;
    const filled = Math.round(width * pct);
    const empty = width - filled;
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

  function alert(qid, sev, msg, where) {
    const sevMap = { critical: 'c-sev-critical', high: 'c-sev-high', medium: 'c-sev-medium', low: 'c-sev-low' };
    return [
      [' ', null],
      [(sev.toUpperCase() + ' '.repeat(10)).slice(0, 9), sevMap[sev]],
      [(qid + ' '.repeat(50)).slice(0, 46), 'c-accent'],
      [(msg + ' '.repeat(60)).slice(0, 38), 'c-primary'],
      [where, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in', '14:25:18', [m(' /use '), a('codeql')], W, 'l1'),
    window.logLine('ok', '14:25:18', [m(' codeql binary '), p('2.16.4'), m(' · packs cached at '), p('~/.codeql')], W, 'l1b'),
    window.logLine('in', '14:25:30', [m(' /run '), a('--language js,rust,python --suite security-extended')], W, 'l2'),
    window.logLine('run', '14:25:30', [m(' codeql:scan · build databases · then run security-extended')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('db build · js       ', 1, 1, 'done · 1.2s',     'c-success')], W, 'p1'),
    window.row([T('   '), ...bar('db build · rust     ', 1, 1, 'done · 18.4s',    'c-success')], W, 'p2'),
    window.row([T('   '), ...bar('db build · python   ', 1, 1, 'done · 0.9s',     'c-success')], W, 'p3'),
    window.row([T('   '), ...bar('queries · js        ', 84, 84, 'done · 7 alerts','c-success')], W, 'p4'),
    window.row([T('   '), ...bar('queries · rust      ', 62, 62, 'done · 4 alerts','c-success')], W, 'p5'),
    window.row([T('   '), ...bar('queries · python    ', 41, 41, 'done · 2 alerts','c-success')], W, 'p6'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('ALERTS · 13 · sarif written', W, 'sec1'),
    window.row(alert('js/sql-injection',                     'critical', 'untrusted flow to db.query',     'apps/web/server.ts:204'), W, 'a1'),
    window.row(alert('rust/sql-injection',                    'critical', 'format! into sqlx::query',       'apps/api/orders.rs:142'), W, 'a2'),
    window.row(alert('js/path-injection',                     'high',     'req.params → fs.readFile',       'apps/web/server.ts:301'), W, 'a3'),
    window.row(alert('rust/insecure-jwt-algorithm',           'high',     'Algorithm::None accepted',       'apps/api/auth/jwt.rs:54'), W, 'a4'),
    window.row(alert('py/command-line-injection',             'high',     'shell=True with user input',     'jobs/worker.py:213'), W, 'a5'),
    window.row(alert('js/xss',                                'medium',   'unsanitized into res.send',      'apps/web/server.ts:78'), W, 'a6'),
    window.row(alert('rust/missing-rate-limit',               'medium',   'no governor on /checkout',       'apps/api/checkout.rs:12'), W, 'a7'),
    window.row(alert('js/open-redirect',                      'medium',   'res.redirect req.query.next',    'apps/web/server.ts:78'), W, 'a8'),
    window.row(alert('rust/regex-injection',                  'medium',   'compiled from request',          'apps/api/search.rs:31'), W, 'a9'),
    window.row(alert('py/insecure-deserialization',           'high',     'pickle.loads from queue',        'jobs/worker.py:88'), W, 'a10'),
    window.row(alert('js/missing-csrf-protection',            'low',      'no csurf on session app',        'apps/web/middleware.ts:44'), W, 'a11'),
    window.row([T('   '), m('   … 2 more · '), a('/open js/sql-injection'), m(' for full path')], W, 'a-more'),
    window.blankRow(W, 'b3'),
    window.logLine('ok', '14:26:48', [
      m(' wrote '), p('.kuzushi/v2/raw/codeql-2026-05-06T14-25.sarif'),
      m(' · '), p('142 KB'),
    ], W, 'l-end'),
    window.logLine('agent', '14:26:48', [
      m(' two CRITICAL sqli alerts overlap with semgrep raw hits — '),
      a('/use sast'), m(' will dedupe.'),
    ], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · codeql · /run security-extended">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'codeql', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'codeql:scan (done) · 13 alerts · sarif 142 KB', findings: 0,
        promptModule: 'codeql',
        keybinds: [
          ['/open', 'js/sql-injection'], ['/use', 'sast (dedupe)'],
          ['/show', 'sarif'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.CodeqlView = CodeqlView;
