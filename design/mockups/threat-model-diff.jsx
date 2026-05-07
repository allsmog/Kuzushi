// threat-model · v2 vs v3 diff toggle

function ThreatModelDiffView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function ch(kind, label, was, now) {
    const map = { add:[' + ','c-success'], rm:[' − ','c-danger'], chg:[' Δ ','c-warn'], same:[' · ','c-subtle'] };
    return [
      [' ', null], map[kind], [' ', null],
      [(label + ' '.repeat(40)).slice(0, 36), 'c-primary'],
      [(was + ' '.repeat(28)).slice(0, 24), kind === 'rm' || kind === 'chg' ? 'c-danger' : 'c-muted'],
      [' → ', 'c-subtle'],
      [(now + ' '.repeat(28)).slice(0, 24), 'c-success'],
    ];
  }

  const lines = [
    window.logLine('in','15:12:01',[m(' /use threat-model '), a('--diff v2..v3')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('v2 '), p('2026-04-12 jen.t · pre-refund-bot'),
      m('   v3 '), p('2026-05-05 jen.t · post-PR412')], W, 'h0'),
    window.row([T('  '), m('summary '), p('+4 actors · +6 attacker stories · −1 boundary · 3 risks reranked')], W, 'h1'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('ACTORS', W, 's1'),
    window.row(ch('add',  'reviewer · 3rd-party',          '—',                        'untrusted (post-onboard)'), W, 'ac1'),
    window.row(ch('add',  'refund-bot · agent',            '—',                        'agent w/ payment tools'), W, 'ac2'),
    window.row(ch('add',  'concierge · agent',             '—',                        'agent w/ read tools'), W, 'ac3'),
    window.row(ch('add',  'review-pipeline · async',       '—',                        'queue → enrichment → bot'), W, 'ac4'),
    window.row(ch('chg',  'customer · trusted',            'trusted',                  'untrusted (assume hostile)'), W, 'ac5'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('TRUST BOUNDARIES', W, 's2'),
    window.row(ch('rm',   'web ↔ api (legacy login)',      'shared session',           'removed · oauth path replaces'), W, 'tb1'),
    window.row(ch('add',  'web → agents/*',                '—',                        'untrusted text → sysmsg'), W, 'tb2'),
    window.row(ch('add',  'redis-q (cross-lang)',          '—',                        'web → worker (jobs/) blob bus'), W, 'tb3'),
    window.row(ch('chg',  'api → libs/payments',           'in-process trust',         'in-process · sensitive ops'), W, 'tb4'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('TOP RISKS · reranked', W, 's3'),
    window.row(ch('chg',  'prompt-injection (refund-bot)', 'rank 9 (medium)',          'rank 1 (CRIT) · $-loss'), W, 'r1'),
    window.row(ch('chg',  'idor on /api/order',            'rank 1 (CRIT)',            'rank 4 (high) · partial fix in v2.1'), W, 'r2'),
    window.row(ch('chg',  'xss in legacy admin',           'rank 5 (high)',            'rank 12 (low) · admin behind sso'), W, 'r3'),
    window.row(ch('add',  'cross-lang taint redis q',      '—',                        'rank 6 (high) · py → ts'), W, 'r4'),
    window.row(ch('rm',   'csrf on /login form',           'rank 14 (low)',            'fixed by F-0007 patch'), W, 'r5'),
    window.blankRow(W, 'b5'),
    window.sectionHeader('IMPLICATIONS · attacker stories', W, 's4'),
    window.row([T('   '), [' + ', 'c-success'], m('  +6 stories pivot through '), p('agents/*'),
      m(' · '), p('S-21'), m('..'), p('S-26')], W, 'i1'),
    window.row([T('   '), [' + ', 'c-success'], m('  +2 stories use '), p('redis-q'),
      m(' as cross-lang vector')], W, 'i2'),
    window.row([T('   '), [' − ', 'c-danger'],  m('  −3 stories closed by '), p('oauth replacement'),
      m(' (formerly '), p('S-04'), m(', '), p('S-05'), m(', '), p('S-08'), m(')')], W, 'i3'),
    window.blankRow(W, 'b6'),
    window.logLine('flow','15:12:14',[m(' '), a('y'), m(' apply v3 (write '),
      p('.kuzushi/threat-model.json'), m(') · '), a('e'), m(' edit · '),
      a('/use threat-model --show v3'), m(' to render full')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · threat-model · v2..v3 diff">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'threat-model', cost: '$0.41' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'threat-model · v2 → v3 · +4 actors · +6 stories', findings: 38,
        promptModule: 'threat-model',
        keybinds: [['y','apply'],['e','edit'],['--show','full v3'],['--explain','rationale']],
      })}
    </window.TermFrame>
  );
}
window.ThreatModelDiffView = ThreatModelDiffView;
