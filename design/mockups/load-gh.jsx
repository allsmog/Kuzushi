// /load gh:acme/checkout#PR412 · github load

function LoadGhView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('in','14:58:01',[m(' /load '), a('gh:acme/checkout#PR412')], W, 'l1'),
    window.logLine('run','14:58:01',[m(' resolving · github api · token '), p('ghp_…m4Hs')], W, 'l2'),
    window.logLine('ok','14:58:02',[m(' '), p('PR #412'), m('  ·  '), p('avi.k → main'),
      m('  ·  '), p('+412 / -208'),  m('  ·  '), p('14 files'),  m('  ·  '), [' open ', 'c-success']], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('PR · #412 — refactor: refund-bot pricing override', W, 's1'),
    window.row([T('   '), m('author    '), p('avi.k'),
      m('   reviewers '), p('jen.t'), m(', '), p('mira.l'),
      m('   ci '), [' green ', 'c-success'],
      m('   merge gate '), p('1 / 2 approvals')], W, 'p1'),
    window.row([T('   '), m('files     '), p('14'),
      m('   most-changed '), p('apps/web/agents/refund-bot.ts'), m(' (+148 / -41)')], W, 'p2'),
    window.row([T('   '), m('languages '), p('ts (61%)'), m(', '), p('rust (28%)'), m(', '), p('yaml (11%)')], W, 'p3'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('CLONE PLAN', W, 's2'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  shallow clone   '), p('git@github.com:acme/checkout'),  m(' · depth=1 · branch '), p('avi.k/refund-pricing')], W, 'cp1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  workspace       '), p('/tmp/kuzushi/gh-acme-checkout-PR412/'),  m(' · ttl 24h')], W, 'cp2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  inherit context '), m('from '), p('acme-checkout'),  m(' (current ws)')], W, 'cp3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  diff context    '), m('rebuild only changed paths · '), p('14 files'),  m(' · est '), p('22s')], W, 'cp4'),
    window.row([T('   '), [' 5 ', 'c-accent'], m('  policy          '), m('PR review mode · network '), p('denied'),
      m(' · patches '), p('staged-only')], W, 'cp5'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('SUGGESTED RUNS', W, 's3'),
    window.row([T('   '), m('· '), a('/scan --diff-only'),                  m('     run sast over the 14 changed files')], W, 's3a'),
    window.row([T('   '), m('· '), a('/use carlini --scope changed'),       m(' carlini hunt scoped to the diff')], W, 's3b'),
    window.row([T('   '), m('· '), a('/use threat-model --diff-only'),      m('  refresh model where the diff touches it')], W, 's3c'),
    window.row([T('   '), m('· '), a('/story --audience pr'),               m('       render review comments as kuzushi memo')], W, 's3d'),
    window.blankRow(W, 'b4'),
    window.row([T('   '), [' i ', 'c-accent'], m('  '), a('y'), m(' confirm clone · '), a('e'), m(' edit plan · '),
      a('n'), m(' cancel · auto-archive in 24h whether you accept or not')], W, 'in1'),
  ];

  return (
    <window.TermFrame title="kuzushi · /load gh:acme/checkout#PR412">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'load', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'load · gh:acme/checkout#PR412 · 14 files · ttl 24h', findings: 38,
        promptModule: 'load',
        keybinds: [['y','clone'],['e','edit'],['n','cancel'],['/scan --diff-only','focused']],
      })}
    </window.TermFrame>
  );
}
window.LoadGhView = LoadGhView;
