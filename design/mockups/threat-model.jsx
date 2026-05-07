// Threat-model view — `/threats build` → DFD ASCII + STRIDE rollup + a
// reviewable patch the operator approves.

function ThreatModelView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const d = (t) => [t, 'c-danger'];
  const s = (t) => [t, 'c-success'];
  const T = (t) => [t, null];

  // ASCII DFD — drawn as rows of segments (works in monospace)
  const dfd = [
    window.row([T('     '), [ '┌────────────┐         ┌─────────────┐         ┌──────────────┐', 'c-subtle']], W, 'd1'),
    window.row([T('     '), ['│ ', 'c-subtle'], a('  user    '), ['│  https  │ ', 'c-subtle'], a(' api edge  '), ['│   sql   │ ', 'c-subtle'], a('  postgres   '), ['│', 'c-subtle']], W, 'd2'),
    window.row([T('     '), ['│ ', 'c-subtle'], m('  browser '), ['│ ──────► │ ', 'c-subtle'], m('  nginx    '), ['│ ──────► │ ', 'c-subtle'], m('  primary db '), ['│', 'c-subtle']], W, 'd3'),
    window.row([T('     '), ['└────────────┘         └──────┬──────┘         └──────┬───────┘', 'c-subtle']], W, 'd4'),
    window.row([T('                                       '), ['│ ', 'c-subtle'], m('jwt'), T('                    '), ['│ ', 'c-subtle'], w('plaintext PII')], W, 'd5'),
    window.row([T('                                       '), ['▼', 'c-subtle'], T('                       '), ['▼', 'c-subtle']], W, 'd6'),
    window.row([T('                              '), ['┌──────────────┐         ┌──────────────┐', 'c-subtle']], W, 'd7'),
    window.row([T('                              '), ['│ ', 'c-subtle'], a(' worker pool  '), ['│  amqp   │ ', 'c-subtle'], a(' s3 (us-east) '), ['│', 'c-subtle']], W, 'd8'),
    window.row([T('                              '), ['│ ', 'c-subtle'], m(' rabbitmq cli '), ['│ ──────► │ ', 'c-subtle'], m(' invoices/    '), ['│', 'c-subtle']], W, 'd9'),
    window.row([T('                              '), ['└──────────────┘         └──────────────┘', 'c-subtle']], W, 'd10'),
  ];

  const stride = [
    window.row([T('   '), [' S ', 'c-sev-high'],   m('Spoofing       '), p('2'), m(' issues  · '), m('jwt without aud-claim, mailgun cname dangling')], W, 'st1'),
    window.row([T('   '), [' T ', 'c-sev-medium'], m('Tampering      '), p('1'), m(' issue   · '), m('worker pool reads unsigned amqp messages')], W, 'st2'),
    window.row([T('   '), [' R ', 'c-sev-low'],    m('Repudiation    '), p('0'), m(' issues')], W, 'st3'),
    window.row([T('   '), [' I ', 'c-sev-critical'], m('Info-disclosure'), p('3'), m(' issues  · '), w('plaintext PII at db→s3 boundary'), m(', '), w('debug logs')], W, 'st4'),
    window.row([T('   '), [' D ', 'c-sev-medium'], m('DoS            '), p('1'), m(' issue   · '), m('no rate-limit on /checkout/confirm')], W, 'st5'),
    window.row([T('   '), [' E ', 'c-sev-high'],   m('Elev-of-priv   '), p('1'), m(' issue   · '), w('admin subdomain shares jwt secret with api')], W, 'st6'),
  ];

  const lines = [
    window.logLine('in', '14:21:04', [m(' /threats '), a('build')], W, 'l1'),
    window.logLine('run', '14:21:04', [m(' threat-model:build · methodology STRIDE · sourcing context-snapshot.json')], W, 'l2'),
    window.logLine('flow', '14:21:06', [m(' assets discovered · 6 stores, 9 trust-boundaries, 14 flows')], W, 'l3'),
    window.logLine('flow', '14:21:09', [m(' agent drafting DFD …')], W, 'l4'),
    window.sectionHeader('DFD · acme-checkout', W, 'sec-dfd'),
    ...dfd,
    window.blankRow(W, 'b1'),
    window.sectionHeader('STRIDE ROLLUP · 8 issues', W, 'sec-st'),
    ...stride,
    window.blankRow(W, 'b2'),
    window.logLine('agent', '14:21:18', [
      [' biggest delta from last model: ', 'c-primary'],
      ['admin.acme-checkout.com', 'c-warn'],
      [' shares the jwt secret.', 'c-primary'],
    ], W, 'l5'),
    window.logLine('flow', '14:21:18', [
      [' recommend split signing keys + audience claim', 'c-muted'],
    ], W, 'l5b'),
    window.logLine('log', '14:21:18', [
      m(' patch ready: '), a('threat-model.json#v3 → v4'),
      m(' · '), [' +12 −3 ', 'c-success'],
    ], W, 'l6'),
    window.logLine('flow', '14:21:18', [
      m(' approve with '), a('/threats apply'), m(' or view diff with '), a('/threats diff'),
    ], W, 'l6b'),
  ];

  return (
    <window.TermFrame title="kuzushi · threat-model · /threats build">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'threat-model', cost: '$0.18' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end-1')}
      {window.footer({
        stage: 'threat-model:build (proposed v4)', findings: 8,
        promptModule: 'threat-model',
        keybinds: [
          ['/threats', 'diff | apply | regen'], ['/randori', 'PASTA'],
          ['/use', 'sast'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.ThreatModelView = ThreatModelView;
