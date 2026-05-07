// /tune sast.agentic.tracer — editor with live diff vs base.

function TuneView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function diff(kind, body) {
    const map = { '+': 'c-success', '-': 'c-danger', ' ': 'c-primary', '@': 'c-warn' };
    return window.row([T(' '), [kind + ' ', map[kind] || 'c-muted'], [body, map[kind] || 'c-primary']], W, body);
  }

  const lines = [
    window.logLine('in','15:17:10',[m(' /tune '), a('sast.agentic.tracer')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('base   '), p('sast.agentic.tracer v8'), m('  ·  '), m('fork → '), p('v9.draft'),
      m('  ·  '), m('saves to '), p('.kuzushi/v2/prompts/sast.agentic.tracer.v9.md')], W, 'h1'),
    window.row([T('  '), m('linter '), [' ✓ no role-leak ', 'c-success'], m(' '), [' ✓ json-out ', 'c-success'],
      m(' '), [' ! 312 tok over budget ', 'c-warn']], W, 'h2'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('DIFF · v8 → v9.draft', W, 's1'),
    diff('@', '@@ -3,3 +3,4 @@'),
    diff(' ', 'You are an offensive security analyst tracing taint inside a Rust + TypeScript'),
    diff(' ', 'codebase. Operate on the workspace snapshot only. Refuse network calls.'),
    diff('+', 'When unsure, downgrade rather than fabricate; favor false-negatives over noise.'),
    diff(' ', ''),
    diff('@', '@@ -18,5 +19,7 @@'),
    diff(' ', 'Halting:'),
    diff(' ', '  - depth>{{depth}} → halt and emit best-effort note'),
    diff('-', '  - cost>{{budget.usd}} or tokens>{{budget.tokens}} → halt'),
    diff('+', '  - cost>{{budget.usd}} or tokens>{{budget.tokens}} → halt and emit partial trace'),
    diff('+', '  - if {{stride.has_repudiation}} skip repudiation sinks (handled by R-actor)'),
    diff(' ', '  - sink already covered by an OPEN finding → DEDUPE, do not re-emit'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('A/B HARNESS · 6 fixtures', W, 's2'),
    window.row([T('   '), p('fix-01  sql-orders     '), m('  v8 promote 0.92  '), m('  v9 promote 0.94  '), [' ↑ ', 'c-success']], W, 'a1'),
    window.row([T('   '), p('fix-02  jwt-alg-none   '), m('  v8 promote 0.86  '), m('  v9 promote 0.88  '), [' ↑ ', 'c-success']], W, 'a2'),
    window.row([T('   '), p('fix-03  pi-concierge   '), m('  v8 promote 0.78  '), m('  v9 promote 0.74  '), [' ↓ ', 'c-warn']], W, 'a3'),
    window.row([T('   '), p('fix-04  redirect-login '), m('  v8 dedupe       '), m('  v9 dedupe       '), [' = ', 'c-muted']], W, 'a4'),
    window.row([T('   '), p('fix-05  cors-null-orig '), m('  v8 suppress     '), m('  v9 suppress     '), [' = ', 'c-muted']], W, 'a5'),
    window.row([T('   '), p('fix-06  redos-search   '), m('  v8 promote 0.81  '), m('  v9 promote 0.83  '), [' ↑ ', 'c-success']], W, 'a6'),
    window.blankRow(W, 'b4'),
    window.logLine('agent','15:17:11',[
      m(' '), a('v9.draft'), m(' nets '), [' +0.04 mean confidence ', 'c-success'],
      m(' but regresses '), [' fix-03 ', 'c-warn'], m(' (–0.04). Investigate before saving.'),
    ], W, 'l2'),
    window.logLine('flow','15:17:11',[
      m(' '), a('s'), m(' save · '), a('r'), m(' run a/b again · '), a('q'), m(' discard · '), a('/show fix-03'), m(' inspect regression'),
    ], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /tune sast.agentic.tracer">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'tune', cost: '$0.06' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'tune · v9.draft · 5 ↑ / 1 ↓ / 0 ✗', findings: 38,
        promptModule: 'tune',
        keybinds: [['s','save'],['r','re-run a/b'],['q','discard'],['/show','regression']],
      })}
    </window.TermFrame>
  );
}
window.TuneView = TuneView;
