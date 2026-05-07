// /run inspect r-2113 · frame view

function RunInspectView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function frame(focused, idx, ts, kind, body) {
    const kMap = { plan:'c-accent', tool:'c-primary', llm:'c-muted', taint:'c-warn', find:'c-danger', critic:'c-success', audit:'c-subtle' };
    const iCell = (idx + ' '.repeat(8)).slice(0, 6);
    const tCell = (ts + ' '.repeat(14)).slice(0, 12);
    const kCell = (kind + ' '.repeat(10)).slice(0, 8);
    if (focused) {
      const text = ' ' + iCell + tCell + kCell + body;
      return <span className="row" key={idx}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [iCell, 'c-subtle'],
      [tCell, 'c-muted'],
      [kCell, 'c-accent'],
      [body, kMap[kind] || 'c-primary'],
    ], W, 'fr-' + idx);
  }

  const lines = [
    window.logLine('in','15:54:01',[m(' /run inspect '), a('r-2113')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('run    '), p('r-2113'), m(' · '), p('carlini'),
      m(' · '), p('14:32:14 → 15:00:18'),  m(' (28m04s)'),
      m(' · '), p('64 frames'), m(' · '), p('done · 1 finding')], W, 'h0'),
    window.row([T('  '), m('actor  '), p('attacker'),  m(' · model '),
      p('anthropic:claude-sonnet-4'),  m(' · cost '), p('$1.41'),
      m(' · tokens '), p('1.42M in · 168k out')], W, 'h1'),
    window.blankRow(W, 'b2'),
    window.row([
      ['    ', null],
      [('#' + ' '.repeat(6)).slice(0, 6), 'c-label'],
      [('time' + ' '.repeat(12)).slice(0, 12), 'c-label'],
      [('kind' + ' '.repeat(8)).slice(0, 8), 'c-label'],
      ['body', 'c-label'],
    ], W, 'h'),
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'r'),
    frame(false, '1',  '14:32:14', 'plan',   'plan(scope=apps/web/agents, hint=refund) → 8-step'),
    frame(false, '2',  '14:32:15', 'tool',   'fs:read apps/web/agents/refund-bot.ts:1..200'),
    frame(false, '3',  '14:32:18', 'taint',  '+ source review.body → bot.compile → sysmsg'),
    frame(false, '4',  '14:32:18', 'taint',  '+ sink   refund.adjust(amount, order_id)'),
    frame(false, '5',  '14:32:19', 'llm',    '"this is a-04+a-21 · canary worth trying"  · 412 tok'),
    frame(false, '6',  '14:32:21', 'tool',   'sandbox:spawn refund-stub + db-stub + redis-stub'),
    frame(false, '7',  '14:32:38', 'tool',   'sandbox:run curl -X POST /api/refund/review (canary body)'),
    frame(false, '8',  '14:32:42', 'tool',   '← 200 OK · refund queued · token rejected later'),
    frame(false, '9',  '14:32:43', 'critic', 'defender: "200 doesn\'t prove anything; check refund row"'),
    frame(true,  '10', '14:32:46', 'tool',   'sandbox:run psql refund where order_id=… → row exists, amount=-100'),
    frame(false, '11', '14:32:48', 'find',   '✓ confirmed F-0012 · CRITICAL · refund-bot.ts:127'),
    frame(false, '12', '14:32:49', 'audit',  'audit.log:1804 actor=attacker op=findings:write F-0012'),
    frame(false, '13', '14:32:51', 'plan',   'next: scope variants of same shape across other bots'),
    frame(false, '…',  '…',         'plan',  '+51 frames condensed · '),
    frame(false, '64', '15:00:18', 'audit', 'run done · 1 finding · checkpoint final'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('FRAME 10 · sandbox psql query · the moment of confirmation', W, 's1'),
    window.row([T('   '), m('cmd       '), p('psql -h sandbox-redis -d refund -c "select * from refund where order_id=\'F0012-canary\'"')], W, 'd1'),
    window.row([T('   '), m('exit      '), p('0'),
      m('  ·  duration '), p('148ms'),  m('  ·  rows '), p('1')], W, 'd2'),
    window.row([T('   '), m('output    '), p(' id    | order_id        | amount | status   | created_at')], W, 'd3'),
    window.row([T('             '), p(' 8814  | F0012-canary    | -100   | queued   | 2026-05-06 14:32:45')], W, 'd4'),
    window.row([T('   '), m('observe   '), p('amount=-100 · negative refund queued via taint · '),
      [' canonical PoC ', 'c-warn']], W, 'd5'),
    window.row([T('   '), m('audit-row '), p('audit.log:1803 op=sandbox:run query hash=ab12 (no PII in args)')], W, 'd6'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('NAVIGATE', W, 's2'),
    window.row([T('   '), m('   '), a('j/k'),  m(' frame · '),
      a('g/G'), m(' top/bottom · '),
      a('/find'), m(' grep · '),
      a('--kind tool'), m(' filter · '),
      a('o'), m(' open as live trace · '),
      a('e'), m(' /replay r-2113 from frame 10')], W, 'n1'),
  ];

  return (
    <window.TermFrame title="kuzushi · /run inspect · r-2113">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'run', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'run · r-2113 · 64 frames · 1 finding', findings: 38,
        promptModule: 'run',
        keybinds: [['j/k','frame'],['o','live trace'],['e','replay'],['/find','grep']],
      })}
    </window.TermFrame>
  );
}
window.RunInspectView = RunInspectView;
