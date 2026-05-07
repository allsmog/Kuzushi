// /budget — set + display run controls.

function RunControlsView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function bar(label, used, cap, color) {
    const w = 28;
    const pct = used / cap;
    const filled = Math.round(w * pct);
    const empty = w - filled;
    return [
      [(label + ' '.repeat(20)).slice(0, 18), 'c-primary'],
      [' [', 'c-subtle'],
      ['█'.repeat(filled), color || (pct > 0.8 ? 'c-warn' : 'c-success')],
      ['░'.repeat(empty), 'c-subtle'],
      ['] ', 'c-subtle'],
      [(`${used.toFixed(2)} / ${cap.toFixed(2)}`).padStart(18), 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in','14:36:01',[m(' /budget')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('CURRENT BUDGETS', W, 's1'),
    window.row([T('   '), ...bar('run                 ', 0.41, 5.00, 'c-success')], W, 'b1a'),
    window.row([T('   '), ...bar('day · 2026-05-06    ', 1.42, 10.00, 'c-success')], W, 'b1b'),
    window.row([T('   '), ...bar('week                ', 6.18, 25.00, 'c-success')], W, 'b1c'),
    window.row([T('   '), ...bar('month · 2026-05     ', 18.40, 100.00, 'c-success')], W, 'b1d'),
    window.row([T('   '), ...bar('org · acme-security ', 412.00, 600.00, 'c-warn')], W, 'b1e'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('CAPS · soft 80% · hard 100%', W, 's2'),
    window.row([T('   '), m('on hit-soft  '), p('pause'), m('   on hit-hard  '), p('refuse'),
      m('   per-actor  '), p('attacker $2.50 · planner $0.80 · narrator $0.30')], W, 'c1'),
    window.row([T('   '), m('rate limit   '), p('80 RPM'), m(' across all providers · current '), p('14 RPM')], W, 'c2'),
    window.row([T('   '), m('reset        '), p('day '), p('00:00 UTC'),
                                m('  ·  week '), p('Mon 00:00'), m('  ·  month '), p('1st 00:00')], W, 'c3'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('RECENT MUTATIONS', W, 's3'),
    window.row([T('   '), m('14:31:55  '), p('jen.t'),  m('  /budget run '), p('5.00'),  m('   raised from 2.50 for /scan')], W, 'm1'),
    window.row([T('   '), m('09:11:42  '), p('jen.t'),  m('  /budget day '), p('10.00'), m('   end-of-week push')], W, 'm2'),
    window.row([T('   '), m('Mon 17:22 '), p('avi.k'),  m('  /budget week '), p('25.00'),m('   pre-pentest')], W, 'm3'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('PROMPTS BEFORE DISPATCH', W, 's4'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('cost > $0.50 / step'),  m('       confirm before dispatch')], W, 'p1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('writes outside .kuzushi'), m('   confirm before write')], W, 'p2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('network egress'),         m('         confirm before egress')], W, 'p3'),
    window.row([T('   '), [' · ', 'c-subtle'],  m('  '), p('reads outside workspace'),  m(' silent')], W, 'p4'),
    window.row([T('   '), [' · ', 'c-subtle'],  m('  '), p('git mutations'),          m('          silent (uses worktree)')], W, 'p5'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','14:36:01',[m(' '), a('/budget run 8.00'),
      m(' · '), a('/cap soft 0.7'), m(' · '), a('/budget reset run')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /budget · /cap">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'budget', cost: '$0.41' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'budget · run 8% · day 14% · org 69%', findings: 38,
        promptModule: 'budget',
        keybinds: [['/budget','set'],['/cap','soft|hard'],['/budget reset','clear']],
      })}
    </window.TermFrame>
  );
}
window.RunControlsView = RunControlsView;
