// Vuln-scout view — plugin-backed audit loop. Loads a vuln-scout plugin
// pack, runs targeted audits, emits a per-question PASS/FAIL ledger.

function VulnScoutView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  function audit(num, q, verdict, ev) {
    const c = verdict === 'PASS' ? 'c-success' : verdict === 'FAIL' ? 'c-danger' : 'c-warn';
    return [
      [' ', null],
      [(num + '   ').slice(0, 5), 'c-subtle'],
      [(q + ' '.repeat(70)).slice(0, 60), 'c-primary'],
      [(verdict + '   ').slice(0, 6), c],
      [ev, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in',  '15:14:08', [m(' /use '), a('vuln-scout')], W, 'l1'),
    window.logLine('ok',  '15:14:08', [m(' plugin '), p('vuln-scout/standard@1.7'), m(' loaded from '), p('$KUZUSHI_VULN_SCOUT_PLUGIN'), m(' · 41 audits')], W, 'l2'),
    window.logLine('in',  '15:14:14', [m(' /run '), a('audit --scope api,web,jobs')], W, 'l3'),
    window.logLine('run', '15:14:14', [m(' vuln-scout:audit · 41 audits · model '), p('openai:gpt-4.1')], W, 'l4'),
    window.blankRow(W, 'b1'),

    window.sectionHeader('AUDIT LEDGER · top 12', W, 'sec-l'),
    window.row(audit('A01', 'Are all DB writes parameterized (no string concat)?',         'FAIL', 'orders.rs:142 — see F-0001'), W, 'a1'),
    window.row(audit('A02', 'Does the auth layer reject alg=none JWTs?',                    'FAIL', 'auth/jwt.rs:54'), W, 'a2'),
    window.row(audit('A03', 'Are CSRF tokens bound to session id?',                          'FAIL', 'web/middleware.ts:44'), W, 'a3'),
    window.row(audit('A04', 'Does every webhook verify a signed envelope?',                  'WARN', 'segment webhook ok; stripe shares secret across envs'), W, 'a4'),
    window.row(audit('A05', 'Is there a session timeout < 24h on privileged routes?',        'PASS', '8h timeout in apps/web/session.ts'), W, 'a5'),
    window.row(audit('A06', 'Do agents have a tool-call allowlist?',                         'WARN', 'agents/runner.ts allows any registered tool'), W, 'a6'),
    window.row(audit('A07', 'Is rate-limit applied to /checkout/*?',                          'FAIL', 'no governor configured'), W, 'a7'),
    window.row(audit('A08', 'Is PII encrypted at rest in the s3 invoice bucket?',             'FAIL', 'sse-s3 only · no kms key'), W, 'a8'),
    window.row(audit('A09', 'Does CI fail on critical sast findings?',                         'PASS', '.github/workflows/sast.yml exit-on-critical'), W, 'a9'),
    window.row(audit('A10', 'Are admin routes on a separate JWT audience?',                   'FAIL', 'shared with api · F-0003'), W, 'a10'),
    window.row(audit('A11', 'Are container images run as non-root?',                            'PASS', 'all 4 services USER app'), W, 'a11'),
    window.row(audit('A12', 'Is logging scrubbed of card numbers?',                              'PASS', 'maskPan() applied at log boundary'), W, 'a12'),
    window.row([T('   '), m('   … '), a('A13..A41'), m(' · '), a('/show audits all')], W, 'a-more'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('ROLLUP · 41 audits · 18 PASS · 14 FAIL · 9 WARN', W, 'sec-r'),
    window.row([T('   '), m('  pass     '), p('44%'), m('  '), [' '.repeat(13), 'c-success'], [' '.repeat(10), 'c-warn'], [' '.repeat(10), 'c-danger'], [' '.repeat(0), 'c-subtle']], W, 'r1'),
    window.row([T('   '), m('  posture  '), w('YELLOW'), m('  · '), p('14 FAILs are concentrated in api/auth + web/middleware')], W, 'r2'),
    window.blankRow(W, 'b3'),

    window.logLine('agent', '15:14:42', [m(' patch '), a('F-0001'), m(' / '), a('F-0003'), m(' / '), a('F-0007'), m(' to flip 3 audits at once. plan with '), a('/use patch F-0003')], W, 'l-end'),
    window.logLine('log', '15:14:42', [m(' wrote '), p('.kuzushi/runs/.../vuln-scout.json'), m(' · csv at '), p('.kuzushi/runs/.../audits.csv')], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · vuln-scout · audit · standard@1.7">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'vuln-scout', cost: '$0.28' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'vuln-scout (done) · 14 fail · 9 warn', findings: 14,
        promptModule: 'vuln-scout',
        keybinds: [
          ['/show', 'audits all'], ['/use', 'patch F-0003'],
          ['/vuln-scout', 'export'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.VulnScoutView = VulnScoutView;
