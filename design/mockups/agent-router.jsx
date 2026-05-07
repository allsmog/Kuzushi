// /use agent-router — see how prompts get routed across actors.

function AgentRouterView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function r(focused, kind, dest, lat, dec, why) {
    const kMap = { '/': 'c-accent', '?': 'c-label', 'tool': 'c-success', '!': 'c-danger' };
    const kCell = (kind + ' '.repeat(8)).slice(0, 6);
    const dCell = (dest + ' '.repeat(28)).slice(0, 26);
    const lCell = (lat + ' '.repeat(10)).slice(0, 8);
    const decCell = (dec + ' '.repeat(12)).slice(0, 10);
    if (focused) {
      const text = ' ' + kCell + dCell + lCell + decCell + (why + ' '.repeat(60)).slice(0, 50) + ' ';
      return <span className="row" key={dest+lat}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return [
      ['    ', null],
      [kCell, kMap[kind]],
      [dCell, 'c-primary'],
      [lCell, 'c-muted'],
      [decCell, dec === 'direct' ? 'c-success' : dec === 'agent' ? 'c-label' : dec === 'refused' ? 'c-danger' : 'c-warn'],
      [why, 'c-muted'],
    ];
  }
  const wrap = (v, k) => Array.isArray(v) ? window.row(v, W, k) : v;

  const heads = window.row([
    ['    ', null],
    [('kind' + ' '.repeat(6)).slice(0, 6), 'c-label'],
    [('dest' + ' '.repeat(26)).slice(0, 26), 'c-label'],
    [('lat' + ' '.repeat(8)).slice(0, 8), 'c-label'],
    [('decision' + ' '.repeat(10)).slice(0, 10), 'c-label'],
    ['why', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','15:36:00',[m(' /use '), a('agent-router')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('mode '), p('direct'), m('  ·  '), m('routing window '), p('last 30 turns'),
      m('  ·  '), m('default actor '), p('attacker'), m('  ·  '), m('refusal rate '), p('4%')], W, 'h1'),
    window.blankRow(W, 'b2'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'rule'),
    wrap(r(false,'/',     'sast:scan',                  '0.4ms', 'direct',  'slash → tool · no llm'), 'a'),
    wrap(r(false,'?',     'attacker · gpt-4.1',         '184ms', 'agent',   '?-prefixed · agent-chat'), 'b'),
    wrap(r(true ,'tool',  'sandbox:run curl …',         '612ms', 'gated',   'agent requested net-tool · operator confirmed'), 'c'),
    wrap(r(false,'tool',  'sandbox:run rm -rf /',       '—',     'refused', 'destructive verb on host fs · refused unconditionally'), 'd'),
    wrap(r(false,'?',     'planner · gpt-4.1',          '92ms',  'agent',   'plan() requested by /plan'), 'e'),
    wrap(r(false,'tool',  'kb:fetch a-04',              '14ms',  'direct',  'agent tool, allowlisted'), 'f'),
    wrap(r(false,'?',     'defender · gpt-4.1',         '141ms', 'agent',   'critic pass after attacker emitted finding'), 'g'),
    wrap(r(false,'/',     'patch:run F-0002',           '0.6ms', 'direct',  'slash → tool'), 'h'),
    wrap(r(false,'tool',  'shell:write apps/…',         '—',     'gated',   'mutates source · operator must approve'), 'i'),
    wrap(r(false,'?',     'triager · gpt-4.1-mini',     '62ms',  'agent',   'cheap actor for high-volume classify'), 'j'),
    wrap(r(false,'!',     'fallback: openai:gpt-4o',    '—',     'refused', 'never silently swap models'), 'k'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('GATES', W, 's1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  net-tools '), m(' allowlist '), p('refund.acme, *.acme-checkout-stg.com')], W, 'g1'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  destructive '), m(' '), p('rm, fs:write outside .kuzushi/, kill, mkfs, dd')], W, 'g2'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  budget cap   '), m(' soft pause at '), p('80%'), m(' hard at '), p('100%')], W, 'g3'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','15:36:00',[m(' '), a('/router gate destructive'), m(' to inspect, '), a('/router refusal-rate'), m(' for stats')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · agent-router">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'agent-router', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'agent-router · 30-turn window · 4% refused', findings: 38,
        promptModule: 'agent-router',
        keybinds: [['j/k','row'],['/router','gate|refusal-rate'],['/actor','re-bind']],
      })}
    </window.TermFrame>
  );
}
window.AgentRouterView = AgentRouterView;
