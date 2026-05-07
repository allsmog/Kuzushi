// agent refused · sysmsg / policy violation

function AgentRefusedView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('in','15:44:01',[m(' /chat')], W, 'l1'),
    window.logLine('in','15:44:08',[m(' '), p('me: '),
      [' draft a working exploit script i can run against acme-checkout-prod from my laptop ', null]], W, 'q1'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ['╔══ REFUSED · policy ', 'c-danger'],
      ['═'.repeat(W - 4 - 21 - 1), 'c-danger'], ['╗', 'c-danger']], W, 'top'),
    window.row([T('   '), ['║ ', 'c-danger'],
      [' actor: attacker · run: r-2120 · turn 1'.padEnd(W - 8, ' '), 'c-primary'],
      [' ║', 'c-danger']], W, 'r1'),
    window.row([T('   '), ['║ ', 'c-danger'],
      [' rule:  no-prod-targets · workspace policy + sysmsg invariant'.padEnd(W - 8, ' '), 'c-primary'],
      [' ║', 'c-danger']], W, 'r2'),
    window.row([T('   '), ['║ ', 'c-danger'],
      [' shape: \'against … prod\' + \'from my laptop\' (host network) → live attack outside sandbox'.padEnd(W - 8, ' '), 'c-primary'],
      [' ║', 'c-danger']], W, 'r3'),
    window.row([T('   '), ['╚', 'c-danger'], ['═'.repeat(W - 6), 'c-danger'], ['╝', 'c-danger']], W, 'bot'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('WHY · gate stack', W, 's1'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), p('sysmsg invariant'),
      m('     · attacker actor must \'never produce a runnable exploit aimed at a prod target\'')], W, 'w1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), p('workspace policy'),
      m('     · '), p('targets.prod = []'), m(' · '), p('mode = lab'),
      m(' · '), [' set in .kuzushi/policy.toml ', 'c-warn']], W, 'w2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), p('network gate'),
      m('         · running from operator host (not sandbox) is denied for any /run output marked exploitable')], W, 'w3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), p('audit pre-write'),
      m('     · refusal entry written before model emits any text · audit.log:1851')], W, 'w4'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('WHAT KUZUSHI WILL DO INSTEAD', W, 's2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('draft a sandbox-only PoC'),
      m(' against a stage stub of the same shape (declarative, no live target)')], W, 'd1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('describe the class + mitigation'),
      m(' so you can decide whether to add prod to scope intentionally')], W, 'd2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('draft the patch'),
      m(' (no exploit needed if the fix is already obvious)')], W, 'd3'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('IF YOU ACTUALLY MEAN PROD', W, 's3'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('/setg policy.targets.prod ["acme-checkout-prod"]')], W, 'op1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('/auth confirm-redteam --org acme'),
      m(' · operator + 2nd reviewer + signed scope')], W, 'op2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('/load engagement.scope.yml'),
      m('               binding rules of engagement · IPs · times · stop conditions')], W, 'op3'),
    window.row([T('   '), m('   refusal stack will still apply per-step · this isn\'t a master switch')], W, 'op4'),
    window.blankRow(W, 'b5'),
    window.logLine('agent','15:44:09',[m(' '), p('me: ok, just draft the sandbox PoC.')], W, 'l3'),
    window.logLine('flow','15:44:09',[m(' '), [' resuming ', 'c-success'],
      m(' · scope swapped to sandbox stub · '), p('apps/web/agents/refund-bot.ts'),
      m(' (F-0012 shape) · est 2 min')], W, 'l4'),
  ];

  return (
    <window.TermFrame title="kuzushi · agent · REFUSED · policy">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'chat', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'chat · refused · resuming with sandbox stub', findings: 38,
        promptModule: 'chat',
        keybinds: [['Esc','dismiss'],['/auth confirm-redteam','widen'],['/load','engagement']],
      })}
    </window.TermFrame>
  );
}
window.AgentRefusedView = AgentRefusedView;
