// /prompt sast.agentic.tracer — view a registered prompt.

function PromptView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function bodyLine(s, c) { return window.row([T(' '), [s, c || 'c-primary']], W, s); }

  const lines = [
    window.logLine('in','15:15:30',[m(' /prompt '), a('sast.agentic.tracer')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('id     '), p('sast.agentic.tracer'), m('  ·  '), m('role '), [' attacker ', 'c-danger'],
      m('  ·  '), m('ver '), p('v8'), m('  ·  '), m('owner '), p('core')], W, 'h1'),
    window.row([T('  '), m('source '), p('apps/kuzushi/native/sast/agentic/prompts/tracer.md'), m('  ·  '), m('hash '), p('sha256:8f1b…02e1')], W, 'h2'),
    window.row([T('  '), m('inputs '), p('finding_seed: TaintSeed'), m(', '), p('budget: Budget'), m(', '), p('depth: u8 = 4')], W, 'h3'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('SYSTEM (rendered, redacted to 24 lines)', W, 's1'),
    bodyLine(' You are an offensive security analyst tracing taint inside a Rust + TypeScript', 'c-primary'),
    bodyLine(' codebase. Operate on the workspace snapshot only. Refuse network calls.'),
    bodyLine(''),
    bodyLine(' Goals (in order):'),
    bodyLine('   1. confirm whether the seed reaches an exploitable sink'),
    bodyLine('   2. shortest dataflow path · prefer single-file inlines'),
    bodyLine('   3. emit a Finding only if reachability ≥ 0.7 confidence'),
    bodyLine(''),
    bodyLine(' Tools available:  workspace:read, workspace:grep, sandbox:run (no net),'),
    bodyLine('                   kb:fetch, finding:promote, finding:downgrade'),
    bodyLine(''),
    bodyLine(' Halting:'),
    bodyLine('   - depth>{{depth}} → halt and emit best-effort note'),
    bodyLine('   - cost>{{budget.usd}} or tokens>{{budget.tokens}} → halt'),
    bodyLine('   - sink already covered by an OPEN finding → DEDUPE, do not re-emit'),
    bodyLine(''),
    bodyLine(' Output (strict json):'),
    bodyLine('   { verdict: "promote"|"dedupe"|"halt",'),
    bodyLine('     finding?: { severity, name, file, line, evidence[] },'),
    bodyLine('     dedupes?: [alias],'),
    bodyLine('     trace: [Step] }'),
    bodyLine(''),
    bodyLine(' Style:'),
    bodyLine('   - terse · evidence-first · no apologies · no scope-creep'),
    bodyLine('   - cite kb chunks by id when claiming a vuln class'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('USER (template)', W, 's2'),
    window.row([T('  '), p('Trace this seed:')], W, 'u1'),
    window.row([T('  '), p('  '), m('{{ render_seed(finding_seed) }}')], W, 'u2'),
    window.row([T('  '), p('Stay within '), m('{{budget.usd}}'), p(' and '), m('{{depth}}'), p(' hops.')], W, 'u3'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','15:15:30',[
      m(' '), a('/tune sast.agentic.tracer'), m(' to fork v9 · '), a('/prompt diff v7..v8'), m(' to compare'),
    ], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /prompt sast.agentic.tracer">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/prompt sast.agentic.tracer v8', findings: 38,
        keybinds: [['t','/tune'],['d','/prompt diff'],['c','copy'],['/back','prompts']],
      })}
    </window.TermFrame>
  );
}
window.PromptView = PromptView;
