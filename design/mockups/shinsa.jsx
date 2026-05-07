// Shinsa view — ISO 27001 / NIST / SOC 2 compliance scan. Walks controls,
// emits per-control verdict + evidence pointer. "shinsa" = audit/review (審査).

function ShinsaView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function ctrl(id, name, verdict, ev) {
    const verdictColor = verdict === 'PASS' ? 'c-success'
      : verdict === 'FAIL' ? 'c-danger'
      : verdict === 'WARN' ? 'c-warn' : 'c-muted';
    return [
      [' ', null],
      [(id + ' '.repeat(14)).slice(0, 12), 'c-accent'],
      [(name + ' '.repeat(60)).slice(0, 56), 'c-primary'],
      [(verdict + '   ').slice(0, 6), verdictColor],
      [ev, 'c-muted'],
    ];
  }

  function rollup(framework, pass, warn, fail, na) {
    const total = pass + warn + fail + na;
    const w = 30;
    const pp = Math.round(w * pass / total);
    const ww = Math.round(w * warn / total);
    const ff = Math.round(w * fail / total);
    const nn = w - pp - ww - ff;
    return [
      [' ', null],
      [(framework + ' '.repeat(20)).slice(0, 18), 'c-primary'],
      [' [', 'c-subtle'],
      ['█'.repeat(pp), 'c-success'],
      ['█'.repeat(ww), 'c-warn'],
      ['█'.repeat(ff), 'c-danger'],
      ['░'.repeat(nn), 'c-subtle'],
      ['] ', 'c-subtle'],
      [`${pass}P `, 'c-success'],
      [`${warn}W `, 'c-warn'],
      [`${fail}F `, 'c-danger'],
      [`${na}— `, 'c-muted'],
      ['  of ', 'c-muted'],
      [`${total}`, 'c-primary'],
    ];
  }

  const lines = [
    window.logLine('in', '15:01:11', [m(' /use '), a('shinsa')], W, 'l1'),
    window.logLine('in', '15:01:18', [m(' /run '), a('--frameworks iso27001,nist-csf,soc2 --evidence on')], W, 'l2'),
    window.logLine('run', '15:01:18', [m(' shinsa · walking '), p('312'), m(' controls across 3 frameworks')], W, 'l3'),
    window.blankRow(W, 'b1'),

    window.sectionHeader('FRAMEWORK ROLLUP', W, 'sec-roll'),
    window.row(rollup('ISO 27001:2022',   78, 9, 4,  2), W, 'r1'),
    window.row(rollup('NIST CSF 2.0',     54, 6, 2,  4), W, 'r2'),
    window.row(rollup('SOC 2 · TSC 2017', 41, 8, 3, 11), W, 'r3'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('FAILURES · 9 controls', W, 'sec-fail'),
    window.row(ctrl('A.5.15',  'Access control policy — last review > 12 months',           'FAIL', 'docs/policies/access.md (mtime 2024-09-12)'), W, 'f1'),
    window.row(ctrl('A.8.24',  'Cryptography use of approved algorithms',                  'FAIL', 'apps/api/auth/jwt.rs:54 · alg=None path'), W, 'f2'),
    window.row(ctrl('A.8.28',  'Secure coding — secret material in source',               'FAIL', 'see secret-scan suspects · 4 entries'), W, 'f3'),
    window.row(ctrl('CC6.1',   'Logical access — privileged accounts inventoried',        'FAIL', '.kuzushi/inventory.yaml absent'), W, 'f4'),
    window.row(ctrl('CC7.2',   'Detection of anomalies in security operations',           'FAIL', 'no on-call alerting wired into agent runs'), W, 'f5'),
    window.row(ctrl('PR.AC-7', 'Users / devices authenticated proportional to risk',      'FAIL', 'admin subdomain shares jwt secret · F-0003'), W, 'f6'),
    window.row(ctrl('A.5.34',  'Privacy — PII handling documented',                        'FAIL', 'plaintext PII at db→s3 boundary · STRIDE-I'), W, 'f7'),
    window.row(ctrl('CC2.3',   'Communication of changes to internal users',              'FAIL', 'CHANGELOG.md last entry 2025-11-04'), W, 'f8'),
    window.row(ctrl('A.8.16',  'Monitoring activities — log retention',                    'FAIL', 'cloudwatch retention 7d · policy says 90d'), W, 'f9'),
    window.blankRow(W, 'b3'),

    window.sectionHeader('WARNINGS · 23 (top 5)', W, 'sec-warn'),
    window.row(ctrl('A.5.7',   'Threat intelligence — refreshed quarterly',                'WARN', 'KEV last pulled 2h ago · attack 14d ago'), W, 'w1'),
    window.row(ctrl('A.8.32',  'Change management — peer review for prod',                 'WARN', '12 of 14 last PRs had 1 reviewer'), W, 'w2'),
    window.row(ctrl('CC1.4',   'Hiring — background checks',                                'WARN', 'evidence link 404 · re-attest needed'), W, 'w3'),
    window.row(ctrl('PR.IP-12','Vulnerability management plan',                             'WARN', 'plan present · SLA undefined'), W, 'w4'),
    window.row(ctrl('A.7.7',   'Clear desk / clear screen',                                 'WARN', 'macbooks not enrolled in Kandji'), W, 'w5'),
    window.row([T('   '), m('   … 18 more · '), a('/show warnings all')], W, 'w-more'),
    window.blankRow(W, 'b4'),

    window.logLine('log', '15:01:42', [m(' wrote '), p('.kuzushi/shinsa/2026-05-06.csv'), m(' (audit-ready) · sign with '), a('/shinsa attest')], W, 'l-end'),
    window.logLine('agent', '15:01:42', [
      m(' 4 of 9 failures resolve if '), a('F-0001'), m(' & '), a('F-0003'), m(' ship — start with '), a('/use patch F-0003'),
    ], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · shinsa · ISO 27001 + NIST CSF + SOC 2">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'shinsa', cost: '$0.22' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'shinsa (done) · 9 fail · 23 warn', findings: 9,
        promptModule: 'shinsa',
        keybinds: [
          ['/show', 'failures all'], ['/shinsa', 'attest | export'],
          ['/use', 'patch F-0003'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.ShinsaView = ShinsaView;
