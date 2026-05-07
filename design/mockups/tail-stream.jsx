// /tail · stream module logs (tail -f equivalent)

function TailStreamView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function L(ts, kind, body, level) {
    const lvl = { info:'c-muted', dbg:'c-subtle', warn:'c-warn', err:'c-danger', ok:'c-success' };
    return [
      [' ', null],
      [(ts + ' '.repeat(20)).slice(0, 14), 'c-subtle'],
      [(kind + ' '.repeat(10)).slice(0, 8), 'c-accent'],
      [body, lvl[level] || 'c-primary'],
    ];
  }

  const lines = [
    window.logLine('in','15:32:01',[m(' /tail '), a('agentic-sast'), m(' '), a('--follow')], W, 'l1'),
    window.row([T('  '), m('source '), p('.kuzushi/runs/r-2118/logs/agent.ndjson'),
      m(' · level '), p('debug'), m(' · '), [' streaming ', 'c-success']], W, 'h0'),
    window.blankRow(W, 'b1'),
    window.row(L('15:32:01.412', 'plan',     'plan(scope=apps/web/agents, h=2) → 8-step',                'info'), W, 'L1'),
    window.row(L('15:32:01.418', 'tool',     'grep -rn "review.body" apps/web/ → 14 hits',                'info'), W, 'L2'),
    window.row(L('15:32:01.421', 'dbg',      'rate limit anthropic: 1/4 used · 200ms cooldown',           'dbg'),  W, 'L3'),
    window.row(L('15:32:01.624', 'tool',     'fs:read apps/web/agents/refund-bot.ts:120..160',            'info'), W, 'L4'),
    window.row(L('15:32:01.711', 'taint',    '+ source: review.body (untrusted)',                          'info'), W, 'L5'),
    window.row(L('15:32:01.712', 'taint',    '+ propagate: bot.compile(review.body) → sysmsg',             'info'), W, 'L6'),
    window.row(L('15:32:01.712', 'taint',    '+ sink: refund.adjust(amount, order_id) reachable',          'warn'), W, 'L7'),
    window.row(L('15:32:01.712', 'find',     '▸ candidate: refund-bot.ts:127 (a-04 + a-21)',               'warn'), W, 'L8'),
    window.row(L('15:32:02.014', 'llm',      'compose poc-3.json · 412 tok in · 188 tok out · 0.014',      'info'), W, 'L9'),
    window.row(L('15:32:02.018', 'tool',     'sandbox:run curl -X POST stub://refund.acme/review',          'info'), W, 'L10'),
    window.row(L('15:32:02.621', 'tool',     '← 200 OK · refund queued · token rejected later',             'ok'),   W, 'L11'),
    window.row(L('15:32:02.624', 'critic',   'defender · "200 doesn\'t prove anything; check refund row"', 'info'), W, 'L12'),
    window.row(L('15:32:02.812', 'tool',     'sandbox:run psql -c "select * from refund where order_id=…"', 'info'), W, 'L13'),
    window.row(L('15:32:02.918', 'tool',     '← row exists · amount=-100 · status=queued',                   'warn'), W, 'L14'),
    window.row(L('15:32:02.921', 'find',     '✓ confirmed F-0012 · CRITICAL · refund-bot.ts:127',            'err'),  W, 'L15'),
    window.row(L('15:32:02.924', 'tool',     'fs:write .kuzushi/runs/r-2118/findings/F-0012.json',           'info'), W, 'L16'),
    window.row(L('15:32:02.928', 'audit',    'audit.log:1844 actor=attacker op=findings:write F-0012',       'info'), W, 'L17'),
    window.row(L('15:32:02.931', 'plan',     'next: continue or stop on first crit? operator option',       'info'), W, 'L18'),
    window.row(L('15:32:02.932', 'pause',    'budget hit on stop_on_critical=true · halting',                'warn'), W, 'L19'),
    window.row(L('15:32:02.940', 'ok',       'paused at frame 18/64 · checkpoint written',                   'ok'),   W, 'L20'),
    window.blankRow(W, 'b2'),
    window.row([T('   '), [' ⏵ ', 'c-warn'], m('  awaiting next event…')], W, 'foot'),
    window.blankRow(W, 'b3'),
    window.row([T('   '), [' i ', 'c-accent'], m('  '), a('Esc'), m(' detach (run keeps going) · '),
      a('/grep'), m(' filter · '), a('--level info'), m(' raise · '), a('--module *'),
      m(' multi-tail')], W, 'in1'),
  ];

  return (
    <window.TermFrame title="kuzushi · /tail · agentic-sast · streaming">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'tail', cost: '$0.014' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'tail · agentic-sast · 20 lines · paused', findings: 38,
        promptModule: 'tail',
        keybinds: [['Esc','detach'],['/grep','filter'],['--level','raise'],['/clear','reset']],
      })}
    </window.TermFrame>
  );
}
window.TailStreamView = TailStreamView;
