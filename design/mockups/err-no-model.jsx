// Error: no-model. Refusing dispatch when no provider key is configured.

function ErrNoModelView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('in','14:02:18',[m(' /use '), a('agentic-sast')], W, 'l1'),
    window.logLine('in','14:02:24',[m(' /run agentic-sast:scan')], W, 'l2'),
    window.logLine('err','14:02:24',[
      m(' '), [' agentic-sast:scan refused ', 'c-danger'], m(' · no model configured for role '), p('attacker'),
    ], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('WHY', W, 's1'),
    window.row([T('   '), m('role         '), p('attacker'), m('  binds to '), p('anthropic:claude-sonnet-4'),
      m('  (per '), p('/actor'), m(')')], W, 'w1'),
    window.row([T('   '), m('credentials  '), m(' '), [' ✗ ', 'c-danger'], m('  '), p('ANTHROPIC_API_KEY'), m(' not set'),
      m('  ·  '), m(' '), [' ✗ ', 'c-danger'], m('  '), p('~/.kuzushi/v2/credentials.toml'), m(' has no anthropic entry')], W, 'w2'),
    window.row([T('   '), m('fallback     '), m('disabled · kuzushi never silently switches model under you')], W, 'w3'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('FIX', W, 's2'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('/auth login anthropic'), m('   browser flow · creds saved to credentials.toml')], W, 'f1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('/actor attacker model openai:gpt-4.1'),
      m('   re-bind role to a model you do have')], W, 'f2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('export ANTHROPIC_API_KEY=sk-ant-…'),
      m('   env-var; precedence over credentials.toml')], W, 'f3'),
    window.blankRow(W, 'b3'),
    window.logLine('flow','14:02:24',[
      m(' run '), a('doctor'), m(' for the full preflight  ·  see '), a('/auth'), m(' for provider state'),
    ], W, 'l4'),
  ];

  return (
    <window.TermFrame title="kuzushi · agentic-sast · NO MODEL CONFIGURED">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'agentic-sast', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'agentic-sast · refused · no model', findings: 38,
        promptModule: 'agentic-sast',
        keybinds: [['/auth','login'],['/actor','re-bind'],['doctor','preflight'],['/back','catalog']],
      })}
    </window.TermFrame>
  );
}
window.ErrNoModelView = ErrNoModelView;
