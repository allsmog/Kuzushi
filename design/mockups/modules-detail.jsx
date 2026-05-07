// /modules detail · one-module deep view

function ModulesDetailView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function tool(name, scope, audited) {
    return [
      [' ', null], [' · ', 'c-subtle'],
      [(name + ' '.repeat(28)).slice(0, 26), 'c-primary'],
      [(scope + ' '.repeat(20)).slice(0, 18), 'c-accent'],
      [audited ? ' ✓ audited ' : ' · ', audited ? 'c-success' : 'c-subtle'],
    ];
  }

  const lines = [
    window.logLine('in','15:52:01',[m(' /modules show '), a('agentic-sast')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('MODULE · agentic-sast', W, 's1'),
    window.row([T('   '), m('id          '), p('agentic-sast'),  m('   category '), p('OFFENSE'),
      m('   stable    '), p('yes'),  m('   since '), p('v0.12')], W, 'd1'),
    window.row([T('   '), m('description '), p('LLM-driven dataflow + variant hunt over the workspace')], W, 'd2'),
    window.row([T('   '), m('shape       '), p('plan → grep → fs:read → taint-step → critic → finding')], W, 'd3'),
    window.row([T('   '), m('alias       '), p('asast'),  m('   subcommands '), p('scan'), m(', '), p('hunt'), m(', '), p('explain')], W, 'd4'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('OPTIONS', W, 's2'),
    window.row([T('   '), m('scope            '), p('apps/web/agents/*'), m(' (project)')], W, 'o1'),
    window.row([T('   '), m('budget           '), p('$2.50 / run'),  m('   tokens '), p('200k in / 8k out')], W, 'o2'),
    window.row([T('   '), m('actor            '), p('attacker · anthropic:claude-sonnet-4 · h2')], W, 'o3'),
    window.row([T('   '), m('triage           '), p('on'),  m('   floor '), p('high')], W, 'o4'),
    window.row([T('   '), m('classes-of-interest '), p('a-04, a-08, a-13, a-21, a-29')], W, 'o5'),
    window.row([T('   '), m('checkpoint-every '), p('20 frames')], W, 'o6'),
    window.row([T('   '), m('parallelism      '), p('1 (sequential)'),  m('   '), [' i sandboxed ', 'c-success']], W, 'o7'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('TOOLS · 8 bound', W, 's3'),
    window.row([T('   '), ...tool('grep',          'workspace ro',  true)], W, 't1'),
    window.row([T('   '), ...tool('fs:read',       'workspace ro',  true)], W, 't2'),
    window.row([T('   '), ...tool('taint-step',     'analysis',     true)], W, 't3'),
    window.row([T('   '), ...tool('kb:fetch',      'kb ro',         true)], W, 't4'),
    window.row([T('   '), ...tool('sandbox:run',   'sandbox · net+', true)], W, 't5'),
    window.row([T('   '), ...tool('fs:write',      'findings only', true)], W, 't6'),
    window.row([T('   '), ...tool('llm:complete',  'actor binding', true)], W, 't7'),
    window.row([T('   '), ...tool('audit:log',     'append-only',   true)], W, 't8'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('PROMPTS', W, 's4'),
    window.row([T('   '), m('system  '), p('prompts/agentic-sast/system.md'),  m('   v3 · 2026-04-22 · jen.t')], W, 'p1'),
    window.row([T('   '), m('plan    '), p('prompts/agentic-sast/plan.md'),     m('   v2 · 2026-03-08 · avi.k')], W, 'p2'),
    window.row([T('   '), m('critic  '), p('prompts/agentic-sast/critic.md'),    m('   v1 · 2026-02-14 · jen.t')], W, 'p3'),
    window.row([T('   '), m('finding '), p('prompts/agentic-sast/finding.md'),    m('   v2 · 2026-04-12 · jen.t')], W, 'p4'),
    window.blankRow(W, 'b5'),
    window.sectionHeader('STATS · last 7d', W, 's5'),
    window.row([T('   '), m('runs    '), p('22'),  m('   findings '), p('+34'),
      m('   patches '), p('+8'),  m('   spend '), p('$2.18 / week')], W, 'st1'),
    window.row([T('   '), m('p50     '), p('5m12s'),  m('   p95 '), p('11m48s'),
      m('   refusals '), p('2 (history-rewrite + imds)')], W, 'st2'),
    window.row([T('   '), m('top fix shapes  '), p('role-tag user · 6 fixes · 24 saved $'),
      m('   '), p('separate planner/actor · 2 fixes')], W, 'st3'),
    window.blankRow(W, 'b6'),
    window.sectionHeader('NEXT', W, 's6'),
    window.row([T('   '), [' ▸ ', 'c-warn'], m('  '), a('/run agentic-sast'),
      m('  ·  '), a('/show options agentic-sast'),
      m('  ·  '), a('/edit prompt agentic-sast/system'),
      m('  ·  '), a('/show runs agentic-sast --since week')], W, 'n1'),
  ];

  return (
    <window.TermFrame title="kuzushi · /modules show agentic-sast">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'modules', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'modules · agentic-sast · 22 runs / 7d · $2.18', findings: 47,
        promptModule: 'modules',
        keybinds: [['/run','launch'],['/show options','config'],['/edit prompt','tune'],['/show runs','history']],
      })}
    </window.TermFrame>
  );
}
window.ModulesDetailView = ModulesDetailView;
