// /run dep-hygiene · upgrade plan

function DepUpgradeView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function dep(focused, name, cur, target, kev, why) {
    const nCell = (name + ' '.repeat(28)).slice(0, 24);
    const cCell = (cur + ' '.repeat(14)).slice(0, 12);
    const tCell = (target + ' '.repeat(14)).slice(0, 12);
    const kCell = (kev + ' '.repeat(10)).slice(0, 8);
    const wCell = why;
    if (focused) {
      const text = ' ' + nCell + cCell + tCell + kCell + wCell;
      return <span className="row" key={name}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [nCell, 'c-primary'],
      [cCell, 'c-muted'],
      [tCell, 'c-success'],
      [kCell, kev === '—' ? 'c-muted' : 'c-danger'],
      [wCell, 'c-muted'],
    ], W, name);
  }

  const lines = [
    window.logLine('in','15:40:01',[m(' /run dep-hygiene '), a('--upgrade-plan')], W, 'l1'),
    window.logLine('run','15:40:01',[m(' lockfiles '), p('Cargo.lock + package-lock.json + uv.lock'),
      m(' · advisories '), p('cisa-kev'), m(' + '), p('rustsec'), m(' + '), p('npm-audit'),
      m(' + '), p('osv'), m(' · '), p('14:56 fresh')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('summary '), p('41 deps stale'), m('  ·  '),
      p('6 in kev'),  m('  ·  '),
      p('14 majors'),  m('  ·  '),
      p('21 minors'),  m('  ·  '),
      p('plan: 6 critical now, 35 next sprint')], W, 'h0'),
    window.blankRow(W, 'b2'),
    window.row([
      ['    ', null],
      [('package' + ' '.repeat(24)).slice(0, 24), 'c-label'],
      [('current' + ' '.repeat(12)).slice(0, 12), 'c-label'],
      [('target' + ' '.repeat(12)).slice(0, 12), 'c-label'],
      [('kev' + ' '.repeat(8)).slice(0, 8), 'c-label'],
      ['why', 'c-label'],
    ], W, 'h'),
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'r'),
    dep(true,  'postgres-rs',          '0.7.21',  '0.7.24',   'CVE-2026-2941', 'CVE-2026-2941 · auth bypass · 3-day-old kev'),
    dep(false, 'curl',                 '8.6.0',   '8.6.1',    'CVE-2026-2877', 'CVE-2026-2877 · CRLF · 4-day-old kev'),
    dep(false, '@auth/core (npm)',     '0.18.2',  '0.20.4',   '—',             'major · breaks token rotation, eat now'),
    dep(false, 'tokio',                '1.36.0',  '1.45.1',   '—',             'minor · perf + async-trait shape'),
    dep(false, 'reqwest',              '0.11.27', '0.12.12',  '—',             'transitive curl pin · trails curl upgrade'),
    dep(false, 'jsonwebtoken (rs)',    '8.3.0',   '9.3.0',    '—',             'breaks alg=none default — same shape as F-0003'),
    dep(false, 'serde',                '1.0.197', '1.0.219',  '—',             'minor'),
    dep(false, 'pydantic',             '2.6.4',   '2.10.2',   '—',             'pin together with pydantic-settings'),
    dep(false, 'react',                '18.3.1',  '18.3.4',   '—',             'patch'),
    dep(false, 'next',                 '14.2.4',  '15.1.6',   '—',             'major · review middleware breaking change'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('STAGED PLAN · 6 critical now', W, 's1'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), p('postgres-rs 0.7.21 → 0.7.24'),  m('   bump · run /use ndiff CVE-2026-2941 first')], W, 'sp1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), p('curl 8.6.0 → 8.6.1'),            m('               bump · transitive (reqwest)')], W, 'sp2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), p('reqwest 0.11.27 → 0.12.12'),    m('         major · TLS backend default change')], W, 'sp3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), p('jsonwebtoken 8.3 → 9.3'),        m('             major · alg=none gone (good)')], W, 'sp4'),
    window.row([T('   '), [' 5 ', 'c-accent'], m('  '), p('@auth/core 0.18.2 → 0.20.4'),    m('       major · session shape change')], W, 'sp5'),
    window.row([T('   '), [' 6 ', 'c-accent'], m('  '), p('react 18.3.1 → 18.3.4'),         m('              patch')], W, 'sp6'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('SAFETY', W, 's2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('staged-only'),
      m('   · upgrades go through /use patch · operator confirms each')], W, 'sa1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('snapshot per step'),
      m('  ·  rollback any one without unwinding all')], W, 'sa2'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('majors run /run sast --diff-only'),
      m(' · auto-flag any new high+ from upgrade')], W, 'sa3'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','15:40:01',[m(' '), a('y'), m(' draft 6 staged patches · '),
      a('e'), m(' edit plan · '), a('1..6'), m(' just one · '),
      a('/run dep-hygiene --next-sprint'), m(' for the longer tail')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · dep-hygiene · 41 stale · 6 in kev">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'dep-hygiene', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'dep-hygiene · 41 stale · 6 critical · plan ready', findings: 38,
        promptModule: 'dep-hygiene',
        keybinds: [['j/k','row'],['y','draft 6'],['1..6','one'],['e','edit']],
      })}
    </window.TermFrame>
  );
}
window.DepUpgradeView = DepUpgradeView;
