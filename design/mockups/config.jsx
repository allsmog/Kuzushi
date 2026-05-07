// Config view — operator surface for governance. Shows effective merged
// config, auth state, allowlist counts, audit trail. Read-only by default;
// /set edits a key inline.

function ConfigView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const s = (t) => [t, 'c-success'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  function kv(key, val, src, note) {
    return [
      [' ', null],
      [(key + ' '.repeat(40)).slice(0, 32), 'c-muted'],
      [(val + ' '.repeat(40)).slice(0, 36), 'c-primary'],
      [(src + ' '.repeat(20)).slice(0, 18), 'c-accent'],
      [note ? note : '', note ? 'c-warn' : null],
    ];
  }

  const lines = [
    window.logLine('in', '14:05:01', [m(' /use '), a('config')], W, 'l1'),
    window.logLine('in', '14:05:06', [m(' /show '), a('effective')], W, 'l2'),
    window.logLine('run', '14:05:06', [m(' merging '), p('~/.kuzushi/config.toml'), m(' ← '), p('./.kuzushi/config.toml'), m(' ← '), p('env'), m(' ← '), p('flags')], W, 'l3'),
    window.blankRow(W, 'b1'),

    window.sectionHeader('AUTH · 3 providers', W, 'sec-auth'),
    window.row([T('   '), [' ✓ ', 'c-success'], p('openai'),     m('     '), p('sk-…vQ8R'), m('  · keychain · last used 2m ago')], W, 'au1'),
    window.row([T('   '), [' ✓ ', 'c-success'], p('anthropic'),  m('  '), p('sk-ant-…pZ12'), m(' · keychain · last used 14h ago')], W, 'au2'),
    window.row([T('   '), [' ! ', 'c-warn'],    p('github'),     m('     '), w('expired 3d ago'), m('  · '), a('/auth github'), m(' to refresh')], W, 'au3'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('EFFECTIVE CONFIG · 12 keys', W, 'sec-eff'),
    window.row(kv('model.default',           'openai:gpt-4.1',           'project',  null), W, 'k1'),
    window.row(kv('model.budget.usd',        '5.00 / run',               'user',     null), W, 'k2'),
    window.row(kv('model.routing',           'direct',                   'default',  null), W, 'k3'),
    window.row(kv('triage.auto',             'on',                       'project',  null), W, 'k4'),
    window.row(kv('triage.severity-floor',   'medium',                   'env',      'KUZUSHI_TRIAGE_FLOOR'), W, 'k5'),
    window.row(kv('findings.store',          '.kuzushi/v2/findings.sqlite3', 'default', null), W, 'k6'),
    window.row(kv('runs.retention',          '90d',                      'user',     null), W, 'k7'),
    window.row(kv('telemetry',               'off',                      'project',  null), W, 'k8'),
    window.row(kv('agent.tool.allowlist',    'grep,read_file,taint-step,write_patch', 'project', null), W, 'k9'),
    window.row(kv('agent.tool.network',      'denied',                   'project',  null), W, 'k10'),
    window.row(kv('approval.patches',        'human-required',           'project',  null), W, 'k11'),
    window.row(kv('approval.threat-model',   'human-required',           'project',  null), W, 'k12'),
    window.blankRow(W, 'b3'),

    window.sectionHeader('ALLOWLISTS', W, 'sec-allow'),
    window.row([T('   '), m('paths excluded     '), p('14'),  m(' patterns ('), p('node_modules, dist, vendor, …'), m(')')], W, 'la1'),
    window.row([T('   '), m('rules disabled     '), p('3'),   m(' ('), p('js/insecure-randomness'), m(', '), p('rust/unwrap'), m(', '), p('py/print-debug'), m(')')], W, 'la2'),
    window.row([T('   '), m('findings suppressed'), p('2'),   m(' (with reason · auto-expire 30d)')], W, 'la3'),
    window.blankRow(W, 'b4'),

    window.sectionHeader('AUDIT TRAIL · last 6 mutations', W, 'sec-aud'),
    window.row([T('   '), m('2026-05-06 09:11  '), p('jen.t'),  m('  set triage.severity-floor → '), p('medium'), m('  ('), a('config:edit'), m(')')], W, 'au-1'),
    window.row([T('   '), m('2026-05-05 16:42  '), p('jen.t'),  m('  applied threat-model v3                ('), a('threat-model:apply'), m(')')], W, 'au-2'),
    window.row([T('   '), m('2026-05-05 14:18  '), p('avi.k'),  m('  suppressed F-0009 · "tracking via cdn" ('), a('findings:suppress'), m(')')], W, 'au-3'),
    window.row([T('   '), m('2026-05-04 11:02  '), p('jen.t'),  m('  rotated openai key                     ('), a('auth:rotate'), m(')')], W, 'au-4'),
    window.row([T('   '), m('2026-05-04 09:18  '), p('avi.k'),  m('  added rule disable js/insecure-rand    ('), a('config:edit'), m(')')], W, 'au-5'),
    window.row([T('   '), m('2026-05-03 17:55  '), p('avi.k'),  m('  patch applied F-0007 · csrf            ('), a('patch:apply'), m(')')], W, 'au-6'),
    window.blankRow(W, 'b5'),

    window.logLine('log', '14:05:08', [m(' edit a key with '), a('/set <key> <value>'), m(' · audit log at '), p('.kuzushi/v2/audit.log')], W, 'l-end'),
  ];

  return (
    <window.TermFrame title="kuzushi · config · /show effective">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'config', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'config (read-only)', findings: 0,
        promptModule: 'config',
        keybinds: [
          ['/set', '<k> <v>'], ['/auth', 'github'],
          ['/show', 'audit'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.ConfigView = ConfigView;
