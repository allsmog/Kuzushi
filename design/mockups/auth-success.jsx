// /auth login anthropic — completed, success state.

function AuthSuccessView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('ok','14:22:31',[m(' callback received · '), p('user '), p('jen.t@acme.example'),
      m(' · org '), p('acme-security')], W, 'l1'),
    window.logLine('run','14:22:31',[m(' verifying token  '), p('PASS'), m('   probing '), p('models:read'),
      m('  '), p('PASS')], W, 'l2'),
    window.logLine('ok','14:22:32',[m(' wrote '), p('macOS-keychain://kuzushi.anthropic'), m('  ·  redacted in '),
      p('~/.kuzushi/v2/credentials.toml')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('AVAILABLE MODELS · 6', W, 's1'),
    window.row([T('   '), [' ✓ ', 'c-success'], p('claude-opus-4.5'),   m('       ctx 200k · 5.00/in 25.00/out')], W, 'm1'),
    window.row([T('   '), [' ✓ ', 'c-success'], p('claude-sonnet-4'),   m('       ctx 200k · 0.30/in  1.50/out')], W, 'm2'),
    window.row([T('   '), [' ✓ ', 'c-success'], p('claude-3.7-sonnet'), m('     ctx 200k · 0.30/in  1.50/out')], W, 'm3'),
    window.row([T('   '), [' ✓ ', 'c-success'], p('claude-haiku'),      m('          ctx 200k · 0.08/in  0.40/out')], W, 'm4'),
    window.row([T('   '), [' ✓ ', 'c-success'], p('claude-3.5-haiku'),  m('      ctx 200k · 0.08/in  0.40/out')], W, 'm5'),
    window.row([T('   '), [' · ', 'c-subtle'],  p('claude-2.1'),         m(' (legacy) ctx 100k · 0.80/in  2.40/out')], W, 'm6'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('NEXT', W, 's2'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('/actor attacker model anthropic:claude-sonnet-4'),
      m('   bind attacker role')], W, 'n1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('/model anthropic:claude-sonnet-4'),
      m('                 set as session default')], W, 'n2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('/run carlini:hunt'),
      m('                              re-run, now possible')], W, 'n3'),
    window.blankRow(W, 'b3'),
    window.row([T('   '), [' i ', 'c-accent'], m('  rotate any time with '), a('/auth rotate anthropic'),
      m(' · '), a('/auth logout anthropic'), m(' to revoke locally')], W, 'i1'),
    window.blankRow(W, 'b4'),
    window.logLine('agent','14:22:33',[
      m(' '), p('carlini'), m(' was previously refusing · '), [' now possible ', 'c-success'], m(' · run '),
      a('/run carlini:hunt'), m(' to retry'),
    ], W, 'l4'),
  ];

  return (
    <window.TermFrame title="kuzushi · /auth login anthropic · success">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/auth · anthropic ✓ · 6 models', findings: 38,
        keybinds: [['/actor','bind'],['/model','default'],['/run','retry'],['/back','catalog']],
      })}
    </window.TermFrame>
  );
}
window.AuthSuccessView = AuthSuccessView;
