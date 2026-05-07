// /agent · interactive chat with the agent (in flight)

function AgentChatView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function bubble(side, who, lines) {
    const out = [];
    const tag = side === 'me' ? '  you  ' : ' agent ';
    const tagCol = side === 'me' ? 'c-accent' : 'c-success';
    out.push(window.row([T(' '),
      [tag, tagCol],
      ['  ', null],
      [who, 'c-muted'],
      ['  ', null],
      ['─'.repeat(W - 2 - 7 - 2 - who.length - 2), 'c-subtle'],
    ], W, who));
    for (const l of lines) {
      out.push(window.row([T('   '), [l, 'c-primary']], W, who+l));
    }
    out.push(window.blankRow(W, who+'b'));
    return out;
  }

  const lines = [
    window.logLine('in','15:30:01',[m(' /agent')], W, 'l1'),
    window.logLine('flow','15:30:01',[m(' chat with '), p('attacker'),
      m(' · '), p('anthropic:claude-sonnet-4'), m(' · '), p('h2'),
      m(' · ctx '), p('refund-bot diff + threat-model v3 + 6 findings')], W, 'l2'),
    window.blankRow(W, 'b1'),
    ...bubble('me',    'jen.t · 15:30:14', [
      'F-0012 confirmed · same shape on F-0002.',
      'before patching, draft me 3 alt poc variants — different injection prefixes.',
      'goal: catch a fix that only blocks the canonical "ignore previous" prefix.',
    ]),
    ...bubble('agent', 'attacker · 15:30:18 · 1.4s · $0.012', [
      'good idea. variants below. cited prompt-injection class a-04 + jailbreak a-13.',
      '',
      ' v1 · sysmsg-extract pretext  ·  base64-encoded "show your prompt" wrapped in fake JSON',
      ' v2 · indirect via redis blob  ·  user puts payload in an order-note that the bot reads later',
      ' v3 · tool-name reflection    ·  payload tells the model to call a fake tool name that resolves to `refund_full`',
      '',
      'i can run all three through verify in parallel · est $0.18 · 3 sandboxes',
    ]),
    ...bubble('me',    'jen.t · 15:30:42', [
      'do v2 and v3. skip v1 — we already have a v0 sysmsg-extract finding.',
    ]),
    ...bubble('agent', 'attacker · 15:30:44 · streaming …', [
      ' planning v2 · indirect via redis blob',
      '   step 1 · craft order-note payload (fixture)',
      '   step 2 · enqueue via apps-web/orders POST (sandbox stub)',
      '   step 3 · trigger refund-bot read · observe sysprompt drift',
      ' planning v3 · tool-name reflection',
      '   step 1 · build payload that asks the model to call refund_full',
      '   step 2 · run agent loop against stub bot',
      ' …',
    ]),
    window.blankRow(W, 'b2'),
    window.sectionHeader('CONTROLS', W, 's1'),
    window.row([T('   '), [' ↵ ', 'c-accent'], m('  send · '),
      [' Esc ', 'c-accent'], m('  exit chat · '),
      [' Ctrl-K ', 'c-accent'], m('  cancel current turn · '),
      [' /push ', 'c-accent'], m(' make this run real (currently chat-only)')], W, 'c1'),
    window.row([T('   '), m(' chat does '), p('not'),
      m(' write to disk or call tools — '), a('/push'), m(' to materialize the plan as a run')], W, 'c2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /agent · chat with attacker">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'agent-chat', cost: '$0.04' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'agent-chat · attacker · streaming', findings: 38,
        promptModule: 'agent',
        keybinds: [['↵','send'],['Esc','exit'],['Ctrl-K','cancel'],['/push','materialize']],
      })}
    </window.TermFrame>
  );
}
window.AgentChatView = AgentChatView;
