// /workspace switch + archive + prune flow.

function WorkspaceManageView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function ws(focused, mark, name, root, runs, findings, last) {
    const nCell = (name + ' '.repeat(28)).slice(0, 22);
    const rCell = (root + ' '.repeat(36)).slice(0, 32);
    const runCell = (runs + ' '.repeat(10)).slice(0, 8);
    const fCell = (findings + ' '.repeat(12)).slice(0, 10);
    const lCell = (last + ' '.repeat(40)).slice(0, 28);
    const markCell = (mark + ' '.repeat(8)).slice(0, 6);
    if (focused) {
      const text = ' ' + markCell + nCell + rCell + runCell + fCell + lCell;
      return <span className="row" key={name}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [markCell, mark.includes('★') ? 'c-warn' : mark.includes('✗') ? 'c-danger' : 'c-muted'],
      [nCell, 'c-primary'],
      [rCell, 'c-muted'],
      [runCell, 'c-muted'],
      [fCell, 'c-muted'],
      [lCell, 'c-muted'],
    ], W, name);
  }

  const heads = window.row([
    ['    ', null],
    [('mark' + ' '.repeat(6)).slice(0, 6), 'c-label'],
    [('workspace' + ' '.repeat(22)).slice(0, 22), 'c-label'],
    [('root' + ' '.repeat(32)).slice(0, 32), 'c-label'],
    [('runs' + ' '.repeat(8)).slice(0, 8), 'c-label'],
    [('findings' + ' '.repeat(10)).slice(0, 10), 'c-label'],
    ['last activity', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','14:25:08',[m(' /workspace list')], W, 'l1'),
    window.blankRow(W, 'b1'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'rule'),
    ws(false, '★ active', 'acme-checkout',  '~/work/acme-checkout',     '14',  '38 open',  '2m ago'),
    ws(true,  '·',         'acme-mobile',   '~/work/acme-mobile',       '8',   '12 open',  '2 days ago'),
    ws(false, '·',         'kb-public',      '~/work/kb-public',         '3',   '0',         '3 days ago'),
    ws(false, '·',         'segmentpay-vendor','/tmp/sp-vendor-clone',   '6',   '11 open',  'last week'),
    ws(false, '·',         'tof-2026-q2',    '~/work/tof-2026-q2',       '2',   '4 closed', '12d ago'),
    ws(false, '✗ archived','acme-old-monorepo','~/.kuzushi/archive/acme-old',  '47','103 archived','60d ago'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('PROPOSED ACTIONS', W, 's1'),
    window.row([T('   '), [' switch ', 'c-success'], m('   to '), p('acme-mobile'),
      m(' · ctx will rebuild on first /scan')], W, 'a1'),
    window.row([T('   '), [' archive', 'c-warn'],    m('   '), p('tof-2026-q2'), m(' · idle 12d · all findings closed')], W, 'a2'),
    window.row([T('   '), [' prune  ', 'c-danger'],  m('   '), p('acme-old-monorepo'),
      m(' archive · last touched 60d ago · '), p('892 MB'), m(' artifacts')], W, 'a3'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('STORAGE', W, 's2'),
    window.row([T('   '), m('total       '), p('1.42 GB'), m('  ·  '), m('runs '), p('1.18 GB'),
      m('  ·  '), m('artifacts '), p('182 MB'), m('  ·  '), m('findings.sqlite3 '), p('48 MB')], W, 'sv1'),
    window.row([T('   '), m('retention   '), p('90d'), m('  ·  '), m('next gc '), p('2026-05-13 (in 7d)')], W, 'sv2'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','14:25:10',[m(' '), a('enter'), m(' switch · '), a('A'), m(' archive · '),
      a('P'), m(' prune (irreversible) · '), a('/workspace init <path>'), m(' new')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /workspace · list">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'workspace', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'workspaces · 5 active · 1 archived', findings: 38,
        promptModule: 'workspace',
        keybinds: [['j/k','row'],['enter','switch'],['A','archive'],['P','prune']],
      })}
    </window.TermFrame>
  );
}
window.WorkspaceManageView = WorkspaceManageView;
