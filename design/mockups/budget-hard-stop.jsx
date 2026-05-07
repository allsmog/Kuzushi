// budget hard-stop · run halted on cap

function BudgetHardStopView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function bar(label, done, total, color) {
    const w = 60;
    const pct = total === 0 ? 0 : done / total;
    const filled = Math.min(w, Math.round(w * pct));
    return [
      [(label + ' '.repeat(20)).slice(0, 16), 'c-primary'],
      [' [', 'c-subtle'],
      ['█'.repeat(filled), color],
      ['░'.repeat(Math.max(0, w - filled)), 'c-subtle'],
      ['] ', 'c-subtle'],
      [(`$${done.toFixed(2)} / $${total.toFixed(2)}`).padStart(16), 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('run','15:48:01',[m(' '), p('agentic-sast'),
      m(' · turn '), p('118 / 120'),
      m(' · '), [' running ', 'c-warn']], W, 'l1'),
    window.logLine('flow','15:48:14',[m(' '), p('cost approaching cap · auto-pause armed at $2.50')], W, 'l2'),
    window.logLine('err','15:48:18',[m(' '), [' BUDGET CAP HIT ', 'c-danger'],
      m(' · run paused · 2 turns short of plan')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('per-run         ', 2.50, 2.50, 'c-danger')], W, 'p1'),
    window.row([T('   '), ...bar('per-actor (atck)', 3.18, 5.00, 'c-warn')], W, 'p2'),
    window.row([T('   '), ...bar('weekly          ', 6.18, 25.00, 'c-success')], W, 'p3'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('STATE AT PAUSE', W, 's1'),
    window.row([T('   '), m('run             '), p('r-2118'),  m('  module '), p('agentic-sast'),
      m('  actor '), p('attacker · anthropic:claude-sonnet-4')], W, 'd1'),
    window.row([T('   '), m('frame           '), p('118 / 120'),
      m('  · '), p('99% of plan complete'),
      m('  ·  '), p('2 frames remaining: critic-pass + finalize')], W, 'd2'),
    window.row([T('   '), m('findings so far '), p('+9'), m(' · '),
      p('1 critical (F-0050)'), m(', '), p('5 high'), m(', '),
      p('3 medium')], W, 'd3'),
    window.row([T('   '), m('dropped         '), [' nothing ', 'c-success'],
      m(' · run is resumable from frame 118 · checkpoint written')], W, 'd4'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('CHOICES', W, 's2'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('/run agentic-sast --resume r-2118 --raise 0.50'),
      m('   '), p('+$0.50'),  m(' · finishes in ~ 30s')], W, 'c1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('/budget run 5.00'),
      m('                          raise per-run cap globally · audited')], W, 'c2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('/finalize r-2118 --best-effort'),
      m('                  emit findings + memo at frame 118 (skip critic)')], W, 'c3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), a('/abandon r-2118'),
      m('                            keep findings · drop work-in-progress')], W, 'c4'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('CAP POLICY', W, 's3'),
    window.row([T('   '), m('per-run         '), p('$2.50'), m(' (project)')], W, 'cp1'),
    window.row([T('   '), m('per-actor       '), p('$5.00'), m(' (project)'), m(' · attacker · resets daily')], W, 'cp2'),
    window.row([T('   '), m('weekly          '), p('$25.00'), m(' (global)'), m('  resets Mon 00:00 UTC')], W, 'cp3'),
    window.row([T('   '), m('hard?           '), p('yes · hits stop the run cleanly · checkpoint always written')], W, 'cp4'),
    window.row([T('   '), m('soft warning at '), p('75% '), m('and '), p('90%')], W, 'cp5'),
    window.blankRow(W, 'b5'),
    window.row([T('   '), [' i ', 'c-accent'], m('  raising the cap '),
      [' is audited ', 'c-warn'],
      m(' · cosign required if you cross 2× the configured value')], W, 'in1'),
  ];

  return (
    <window.TermFrame title="kuzushi · BUDGET CAP · r-2118 paused">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'agentic-sast', cost: '$2.50' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'budget cap · r-2118 · 118/120 · paused', findings: 47,
        promptModule: 'budget',
        keybinds: [['/run --resume','+$0.50'],['/budget run','raise'],['/finalize','best-effort'],['/abandon','drop wip']],
      })}
    </window.TermFrame>
  );
}
window.BudgetHardStopView = BudgetHardStopView;
