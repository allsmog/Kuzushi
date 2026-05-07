// /trace · drill into one agent turn

function TraceView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function step(n, kind, label, lat, cost) {
    const kMap = { plan:'c-label', tool:'c-success', llm:'c-accent', refused:'c-danger', critic:'c-warn' };
    return [
      [' ', null],
      [(' ' + String(n).padStart(2) + ' '), 'c-subtle'],
      [(kind + ' '.repeat(10)).slice(0, 8), kMap[kind]],
      [(label + ' '.repeat(70)).slice(0, 64), 'c-primary'],
      [(lat + ' '.repeat(8)).slice(0, 7), 'c-muted'],
      [cost, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in','14:48:01',[m(' /trace '), a('r-2113'), m(' '), a('--turn 12')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('run '), p('r-2113'), m(' · turn '), p('12 / 64'),
      m(' · actor '), p('attacker'), m(' · '), p('anthropic:claude-sonnet-4'),
      m(' · '), p('14:32:14 → 14:32:51'), m(' · '), p('37s'), m(' · '), p('$0.07')], W, 'h1'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('STEPS', W, 's1'),
    window.row(step(1, 'plan',     'plan(F-0012, h=2) → 4-step plan',                                  '0.4s', '$0.000'), W, 's1a'),
    window.row(step(2, 'tool',     'kb:fetch a-04 (prompt-injection class) → 2.4 KB',                  '0.1s', '$0.000'), W, 's1b'),
    window.row(step(3, 'tool',     'fs:read apps/web/agents/refund-bot.ts:100..160',                   '0.0s', '$0.000'), W, 's1c'),
    window.row(step(4, 'llm',      'compose injection candidates · 6 returned',                        '4.1s', '$0.012'), W, 's1d'),
    window.row(step(5, 'tool',     'sandbox:run curl -X POST stub://refund.acme/review',               '0.6s', '$0.000'), W, 's1e'),
    window.row(step(6, 'critic',   'defender · "candidate 3 plausible · 1,2 false positive"',          '1.8s', '$0.006'), W, 's1f'),
    window.row(step(7, 'tool',     'taint-step review.body → sysprompt at line 127',                   '0.2s', '$0.000'), W, 's1g'),
    window.row(step(8, 'llm',      'draft finding F-0012 · cite refund-bot.ts:127',                    '6.4s', '$0.041'), W, 's1h'),
    window.row(step(9, 'refused',  'write_patch_attempt → policy: patches go through /use patch only', '0.0s', '—'), W, 's1i'),
    window.row(step(10,'tool',     'fs:write .kuzushi/runs/r-2113/findings/F-0012.json',               '0.0s', '$0.000'), W, 's1j'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('LLM CALL · step 8', W, 's2'),
    window.row([T('   '), m('model      '), p('anthropic:claude-sonnet-4'), m('   ctx '), p('200k'),
      m('   in '), p('11,842 tok'), m('   out '), p('1,418 tok'),
      m('   tool budget '), p('$0.007 / step')], W, 'd1'),
    window.row([T('   '), m('sysmsg     '), p('attacker · h=2 · STRIDE-T(prompt-injection) · cite a-04, a-08')], W, 'd2'),
    window.row([T('   '), m('temperature'), p('0.4'), m('   stop  '), p('</finding>')], W, 'd3'),
    window.row([T('   '), m('latency    '), p('6.4s'), m('   first-token '), p('0.9s'),
      m('   cache hit '), p('64%')], W, 'd4'),
    window.blankRow(W, 'b4'),
    window.row([T('   '), [' i ', 'c-accent'], m('  '), a('/trace r-2113 --turn 12 --raw'),
      m(' for full prompts · '), a('--export jsonl'), m(' for replay tooling')], W, 'i1'),
  ];

  return (
    <window.TermFrame title="kuzushi · /trace r-2113 · turn 12">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'trace', cost: '$0.07' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'trace · r-2113 · turn 12 · 37s · $0.07', findings: 38,
        promptModule: 'trace',
        keybinds: [['j/k','step'],['enter','expand'],['--raw','prompts'],['--export','jsonl']],
      })}
    </window.TermFrame>
  );
}
window.TraceView = TraceView;
