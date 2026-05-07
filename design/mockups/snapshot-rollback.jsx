// /snapshot · /rollback · workspace snapshot ledger

function SnapshotRollbackView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function snap(focused, id, when, kind, label, files, sz) {
    const idCell = (id + ' '.repeat(12)).slice(0, 10);
    const wCell  = (when + ' '.repeat(20)).slice(0, 18);
    const kCell  = (kind + ' '.repeat(14)).slice(0, 12);
    const lCell  = (label + ' '.repeat(50)).slice(0, 46);
    const fCell  = (files + ' '.repeat(8)).slice(0, 6);
    const sCell  = sz;
    if (focused) {
      const text = ' ' + idCell + wCell + kCell + lCell + fCell + sCell;
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [idCell, 'c-accent'],
      [wCell, 'c-muted'],
      [kCell, kind === 'auto' ? 'c-muted' : 'c-warn'],
      [lCell, 'c-primary'],
      [fCell, 'c-muted'],
      [sCell, 'c-muted'],
    ], W, id);
  }

  const lines = [
    window.logLine('in','15:34:01',[m(' /snapshot list')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('count '), p('14'),  m('  ·  '),
      m('disk  '), p('41 MB'),  m('  ·  '),
      m('retain '), p('30d for manual · 7d for auto'),  m('  ·  '),
      m('compress '), p('zstd-3')], W, 'h0'),
    window.blankRow(W, 'b2'),
    window.row([
      ['    ', null],
      [('id' + ' '.repeat(10)).slice(0, 10), 'c-label'],
      [('when' + ' '.repeat(18)).slice(0, 18), 'c-label'],
      [('kind' + ' '.repeat(12)).slice(0, 12), 'c-label'],
      [('label' + ' '.repeat(46)).slice(0, 46), 'c-label'],
      [('files' + ' '.repeat(6)).slice(0, 6), 'c-label'],
      ['size', 'c-label'],
    ], W, 'h'),
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'r'),
    snap(false, 'snap-2117', '15:22:02 today',  'auto · pre-patch', 'F-0002 patcher · pre-write concierge.ts',  '1',  '8 KB'),
    snap(true,  'snap-2113', '14:32:14 today',  'auto · pre-hunt',  'r-2113 carlini · concierge.ts + refund-bot.ts',  '2',  '14 KB'),
    snap(false, 'snap-tag1', '14:08:00 today',  'manual',           '"clean baseline before today\'s exercise" — operator',  '482', '4.2 MB'),
    snap(false, 'snap-2098', 'Mon 17:42',        'auto · pre-verify', 'F-0007 csrf rerun',                                 '1',  '6 KB'),
    snap(false, 'snap-2092', 'Mon 09:11',        'auto · pre-tm',     'threat-model v2 → v3 author run',                    '1',  '12 KB'),
    snap(false, 'snap-tag0', '5 days ago',       'manual',           '"pre-PR412" — avi.k',                                 '482', '4.2 MB'),
    snap(false, 'snap-1942', '5 days ago',       'auto · pre-hunt',  'r-1942 carlini hint=refund+idempotency',              '0',  '< 1 KB'),
    snap(false, 'snap-1781', '12 days ago',      'auto · pre-ndiff', 'CVE-2025-XYZ · refund class · 3 candidates',           '3',  '21 KB'),
    snap(false, 'snap-1442', 'last month',       'auto · pre-deep',  'deep-auditor on libs/payments',                        '0',  '< 1 KB'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('SELECTED · snap-2113', W, 's1'),
    window.row([T('   '), m('captured '), p('14:32:14'),  m('   actor '), p('attacker'),
      m('   reason '), p('pre-write captures by snapshot:auto')], W, 'd1'),
    window.row([T('   '), m('files    ')], W, 'd2'),
    window.row([T('         '), m('   '), p('apps/web/agents/concierge.ts'),  m('  '), p('original'), m(' (4.1 KB)')], W, 'd3'),
    window.row([T('         '), m('   '), p('apps/web/agents/refund-bot.ts'),  m('  '), p('original'), m(' (8.8 KB)')], W, 'd4'),
    window.row([T('   '), m('integrity '), p('sha256 ✓'),  m('   compress '), p('zstd-3 → 14 KB · 28% of source')], W, 'd5'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('ACTIONS', W, 's2'),
    window.row([T('   '), [' r ', 'c-accent'], m('  /rollback snap-2113'),
      m('       restore both files · '), [' confirm dialog ', 'c-warn']], W, 'a1'),
    window.row([T('   '), [' R ', 'c-accent'], m('  /rollback snap-2113 --partial'),
      m(' pick files individually')], W, 'a2'),
    window.row([T('   '), [' d ', 'c-accent'], m('  /diff snap-2113'),
      m('         show diff vs current')], W, 'a3'),
    window.row([T('   '), [' x ', 'c-accent'], m('  /snapshot rm snap-2113'),
      m('   delete · refused if any audit entry depends on it')], W, 'a4'),
    window.row([T('   '), [' n ', 'c-accent'], m('  /snapshot tag "review-x"'),
      m(' new manual snapshot of the entire workspace')], W, 'a5'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','15:34:01',[m(' '), a('/rollback snap-2113'),
      m('  is reversible (creates snap-now first); '), a('/snapshot rm'),
      m('  is not')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /snapshot list · 14 snapshots">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'snapshot', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'snapshot · 14 · 41 MB · 9 auto · 5 manual', findings: 38,
        promptModule: 'snapshot',
        keybinds: [['j/k','row'],['r','rollback'],['d','diff'],['n','tag'],['x','rm']],
      })}
    </window.TermFrame>
  );
}
window.SnapshotRollbackView = SnapshotRollbackView;
