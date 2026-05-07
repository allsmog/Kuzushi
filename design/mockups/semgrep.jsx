// Semgrep view — pure pattern-based SAST. Rule packs run, raw hits emitted,
// no LLM triage. Operator's intent: fast, deterministic, noisy → narrow with /findings.

function SemgrepView() {
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

  function hit(rule, sev, file, line, snippet) {
    const sevMap = { critical: 'c-sev-critical', high: 'c-sev-high', medium: 'c-sev-medium', low: 'c-sev-low' };
    return [
      [' ', null],
      [(sev.toUpperCase() + ' '.repeat(10)).slice(0, 9), sevMap[sev]],
      [(rule + ' '.repeat(40)).slice(0, 38), 'c-accent'],
      [(file + ':' + line + ' '.repeat(40)).slice(0, 32), 'c-muted'],
      [snippet, 'c-primary'],
    ];
  }

  const lines = [
    window.logLine('in', '14:18:01', [m(' /use '), a('semgrep')], W, 'l1'),
    window.logLine('in', '14:18:09', [m(' /run '), a('--config p/owasp-top-ten,p/secrets,p/rust')], W, 'l2'),
    window.logLine('run', '14:18:09', [m(' semgrep:scan · '), p('3 rule packs'), m(' · '), p('612'), m(' files indexed')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('p/owasp-top-ten     ', 612, 612, 'done · 12 hits', 'c-success')], W, 'p1'),
    window.row([T('   '), ...bar('p/secrets           ', 612, 612, 'done · 0 hits',  'c-success')], W, 'p2'),
    window.row([T('   '), ...bar('p/rust              ', 612, 612, 'done · 6 hits',  'c-success')], W, 'p3'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('RAW HITS · 18 · no triage', W, 'sec1'),
    window.row(hit('javascript.express.security.audit.xss',  'high',     'apps/web/server.ts',         '78',  'res.send(`<h1>${q}</h1>`)'), W, 'h1'),
    window.row(hit('rust.lang.security.audit.sqli',          'critical', 'apps/api/orders.rs',         '142', 'format!("WHERE id={}",id)'), W, 'h2'),
    window.row(hit('python.lang.security.audit.shell-exec',  'high',     'jobs/worker.py',             '213', 'subprocess.run(cmd, shell=True)'), W, 'h3'),
    window.row(hit('rust.lang.security.audit.weak-crypto',   'medium',   'apps/api/auth/jwt.rs',       '54',  'alg: Algorithm::None'), W, 'h4'),
    window.row(hit('javascript.express.audit.path-traversal','high',     'apps/web/server.ts',         '301', 'fs.readFile(req.params.f)'), W, 'h5'),
    window.row(hit('javascript.express.audit.open-redirect', 'medium',   'apps/web/server.ts',         '78',  'res.redirect(req.query.next)'), W, 'h6'),
    window.row(hit('javascript.express.audit.csrf-missing',  'medium',   'apps/web/middleware.ts',     '44',  'app.use(session())'), W, 'h7'),
    window.row(hit('rust.lang.security.audit.regex-redos',   'medium',   'apps/api/search.rs',         '31',  'Regex::new(user_pat)'), W, 'h8'),
    window.row(hit('rust.lang.security.audit.cors-null',     'low',      'apps/api/cors.rs',           '12',  '"null".to_string()'), W, 'h9'),
    window.row(hit('javascript.express.audit.cookie-flags',  'low',      'apps/web/session.ts',        '60',  'res.cookie(k,v,{})'), W, 'h10'),
    window.row([T('   '), m('   … 8 more · '), a('/show raw all'), m(' or '), a('/use sast'), m(' to triage')], W, 'h-more'),
    window.blankRow(W, 'b3'),
    window.logLine('agent', '14:18:24', [
      m(' deterministic only — no LLM triage. dedupe with '), a('sast:scan'), m(' to merge across rule packs.'),
    ], W, 'a1'),
    window.logLine('log', '14:18:24', [m(' wrote '), p('.kuzushi/v2/raw/semgrep-2026-05-06T14-18.json')], W, 'l-end'),
  ];

  return (
    <window.TermFrame title="kuzushi · semgrep · /run --config …">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'semgrep', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'semgrep:scan (done) · 18 raw hits', findings: 0,
        promptModule: 'semgrep',
        keybinds: [
          ['/show', 'raw all'], ['/use', 'sast (triage)'],
          ['/findings', 'browse'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.SemgrepView = SemgrepView;
