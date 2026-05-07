// /history · fuzzy search across sessions

function HistorySearchView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function hit(focused, when, cmd, ws, run) {
    const tCell = (when + ' '.repeat(20)).slice(0, 18);
    const cCell = (cmd + ' '.repeat(60)).slice(0, 56);
    const wCell = (ws + ' '.repeat(20)).slice(0, 18);
    const rCell = run;
    if (focused) {
      const text = ' ' + tCell + cCell + wCell + rCell;
      return <span className="row" key={cmd+when}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [tCell, 'c-muted'],
      [cCell, 'c-primary'],
      [wCell, 'c-accent'],
      [rCell, 'c-muted'],
    ], W, cmd+when);
  }

  const heads = window.row([
    ['    ', null],
    [('time' + ' '.repeat(18)).slice(0, 18), 'c-label'],
    [('command' + ' '.repeat(56)).slice(0, 56), 'c-label'],
    [('workspace' + ' '.repeat(18)).slice(0, 18), 'c-label'],
    ['run', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','15:00:01',[m(' /history '), a('refund')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('query '), p('"refund"'), m('   match '), p('14'), m(' / '), p('1,418'),
      m('   scope '), p('all workspaces'), m('   sort '), p('newest')], W, 'h0'),
    window.blankRow(W, 'b2'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'r'),
    hit(false, '14:46:01 today',  '/story --audience triage --since 2h',         'acme-checkout', 'r-2116'),
    hit(true,  '14:30:08 today',  '/use patch F-0002 (concierge prompt-inj)',    'acme-checkout', 'r-2115'),
    hit(false, '14:08:14 today',  '/run carlini:hunt → F-0012 refund-bot',        'acme-checkout', 'r-2113'),
    hit(false, 'Mon 17:42',        '/use verify F-0007 csrf vs refund POST',      'acme-checkout', 'r-2104'),
    hit(false, 'Mon 09:11',        '/use threat-model --review refund flow',      'acme-checkout', 'r-2098'),
    hit(false, '5 days ago',       '/use carlini --hint "refund + idempotency"',   'acme-old',      'r-1942'),
    hit(false, '5 days ago',       '/run agentic-sast scope=apps/web/agents',     'acme-old',      'r-1939'),
    hit(false, '12 days ago',      '/use ndiff CVE-2025-XYZ refund-class',         'acme-mobile',   'r-1781'),
    hit(false, '14 days ago',      '/findings --module refund-bot --since 30d',   'acme-mobile',   'r-1751'),
    hit(false, 'last month',       '/use deep-auditor libs/payments',              'segmentpay',    'r-1442'),
    hit(false, 'last month',       '/use vendor-assessment SegmentPay refund',     'segmentpay',    'r-1411'),
    hit(false, '2026-04-02',       '/run shinsa SOC2-CC8 refund-pipeline',         'tof-2026-q2',   'r-1244'),
    hit(false, '2026-03-28',       '/use carlini --pricing-override flag',         'acme-checkout', 'r-1198'),
    hit(false, '2026-03-21',       '/use patch F-0042 refund-handler XSS',         'acme-checkout', 'r-1112'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('PIVOTS', W, 's2'),
    window.row([T('   '), [' ▸ ', 'c-warn'], a('/replay r-2113'),
      m('   replay the carlini hunt that found F-0012')], W, 'pv1'),
    window.row([T('   '), [' ▸ ', 'c-warn'], a('/show run r-2115 --diff r-2113'),
      m('   what changed between the patch run and the hunt that birthed it')], W, 'pv2'),
    window.row([T('   '), [' ▸ ', 'c-warn'], a('/findings --module agentic-sast --since 30d --grep refund'),
      m('   33 hits')], W, 'pv3'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','15:00:02',[m(' '), a('Ctrl-R'), m(' incremental search · '),
      a('/history --json'), m(' for export · '), a('--clear --before 60d'), m(' to gc')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /history · refund">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'history', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'history · "refund" · 14/1418', findings: 38,
        promptModule: 'history',
        keybinds: [['j/k','row'],['enter','rerun'],['Ctrl-R','isearch'],['/replay','step']],
      })}
    </window.TermFrame>
  );
}
window.HistorySearchView = HistorySearchView;
