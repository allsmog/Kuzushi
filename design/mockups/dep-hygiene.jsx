// Dep-hygiene view — direct + transitive dep audit. Outdated, EOL,
// abandoned, license drift, advisory matches.

function DepHygieneView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
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
      [status, color],
    ];
  }

  function dep(name, cur, latest, kind, kindColor, note) {
    return [
      [' ', null],
      [(name + ' '.repeat(34)).slice(0, 32), 'c-accent'],
      [(cur + ' '.repeat(12)).slice(0, 11), 'c-primary'],
      ['→ ', 'c-subtle'],
      [(latest + ' '.repeat(12)).slice(0, 11), 'c-primary'],
      [(kind + '   ').slice(0, 11), kindColor],
      [note, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in',  '14:58:01', [m(' /use '), a('dep-hygiene')], W, 'l1'),
    window.logLine('in',  '14:58:08', [m(' /run '), a('check --ecosystems npm,cargo,pip --advisories on')], W, 'l2'),
    window.logLine('run', '14:58:08', [m(' dep-hygiene:check · '), p('184'), m(' direct · '), p('1284'), m(' total · 3 ecosystems')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('npm                 ',  98,  98, 'done · 14 issues', 'c-warn')], W, 'p1'),
    window.row([T('   '), ...bar('cargo               ',  62,  62, 'done · 4 issues',  'c-warn')], W, 'p2'),
    window.row([T('   '), ...bar('pip                 ',  24,  24, 'done · 5 issues',  'c-warn')], W, 'p3'),
    window.row([T('   '), ...bar('osv advisory match  ', 1284, 1284, 'done · 6 hits',   'c-danger')], W, 'p4'),
    window.row([T('   '), ...bar('license drift       ', 184, 184, 'done · 1 GPL',     'c-warn')], W, 'p5'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('ADVISORIES · 6 OSV matches', W, 'sec-a'),
    window.row(dep('lodash',         '4.17.20', '4.17.21', 'CVE-21    ', 'c-danger', 'GHSA-35jh-r3h4-6jhm · prototype pollution · in 12 paths'), W, 'a1'),
    window.row(dep('axios',          '0.27.2',  '1.6.7',   'CVE-39402 ', 'c-danger', 'GHSA-wf5p-g6vw-rhxx · CSRF on follow-redirect'), W, 'a2'),
    window.row(dep('openssl-sys',    '0.9.81',  '0.9.99',  'CVE-0727  ', 'c-warn',   'rust-sec advisory · ASN.1 parser'), W, 'a3'),
    window.row(dep('cryptography',   '41.0.5',  '42.0.5',  'CVE-26130 ', 'c-warn',   'NULL deref in PKCS#12'), W, 'a4'),
    window.row(dep('@babel/traverse','7.22.5',  '7.23.7',  'CVE-45133 ', 'c-warn',   'arbitrary code execution in traverse plugin'), W, 'a5'),
    window.row(dep('aiohttp',        '3.9.1',   '3.9.4',   'CVE-30589 ', 'c-warn',   'http request smuggling'), W, 'a6'),
    window.blankRow(W, 'b3'),

    window.sectionHeader('OUTDATED · top 6 (of 23)', W, 'sec-o'),
    window.row(dep('react',          '18.2.0',  '18.3.1',  'minor     ', 'c-muted',  'low-risk · 14 PRs of changelog'), W, 'o1'),
    window.row(dep('typescript',     '5.2.2',   '5.4.5',   'minor     ', 'c-muted',  'minor · gradual'), W, 'o2'),
    window.row(dep('tokio',          '1.32.0',  '1.37.0',  'minor     ', 'c-muted',  'recommended · perf'), W, 'o3'),
    window.row(dep('serde',          '1.0.188', '1.0.197', 'patch     ', 'c-muted',  '—'), W, 'o4'),
    window.row(dep('next',           '13.5.6',  '14.2.3',  'major     ', 'c-warn',   'major · app-router migration'), W, 'o5'),
    window.row(dep('pydantic',       '1.10.13', '2.6.4',   'major     ', 'c-warn',   'major · v2 migration guide'), W, 'o6'),
    window.row([T('   '), m('   … 17 more · '), a('/show outdated all')], W, 'o-more'),
    window.blankRow(W, 'b4'),

    window.sectionHeader('LICENSE · 1 drift · 2 abandoned', W, 'sec-l'),
    window.row([T('   '), [' ! ', 'c-warn'], p('readline-sync@1.4.10'), m('  GPL-3.0-only — incompatible w/ project MIT  ('), a('apps/cli'), m(')')], W, 'l1a'),
    window.row([T('   '), [' · ', 'c-subtle'], p('request@2.88.2'), m('         deprecated 2020-02 · 41 indirect uses')], W, 'l2a'),
    window.row([T('   '), [' · ', 'c-subtle'], p('node-uuid@1.4.8'), m('       deprecated 2017-01 · 3 indirect uses')], W, 'l3a'),
    window.blankRow(W, 'b5'),

    window.logLine('agent', '14:58:42', [m(' fix-set ready: '), p('6 advisories'), m(' close in '), p('14 PRs'), m('. start with '), a('/use patch dep:lodash'), m('.')], W, 'l-end'),
    window.logLine('log', '14:58:42', [m(' wrote '), p('.kuzushi/runs/.../dep-hygiene.json'), m(' · '), p('SBOM at .kuzushi/sbom.spdx.json')], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · dep-hygiene · check --advisories on">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'dep-hygiene', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'dep-hygiene (done) · 6 advisories · 23 outdated', findings: 6,
        promptModule: 'dep-hygiene',
        keybinds: [
          ['/show', 'outdated all'], ['/use', 'patch dep:lodash'],
          ['/dep', 'sbom export'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.DepHygieneView = DepHygieneView;
