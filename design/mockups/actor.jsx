// /actor — bind a role (planner/attacker/defender/triager) to a model+prompt.

function ActorView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function actor(focused, role, model, prompt, temp, budget, blurb) {
    const rMap = { planner: 'c-label', attacker: 'c-danger', defender: 'c-success', triager: 'c-warn', critic: 'c-accent' };
    const rCell = (role + ' '.repeat(12)).slice(0, 10);
    const mCell = (model + ' '.repeat(28)).slice(0, 26);
    const pCell = (prompt + ' '.repeat(28)).slice(0, 26);
    const tCell = (temp + ' '.repeat(8)).slice(0, 6);
    const bCell = (budget + ' '.repeat(12)).slice(0, 10);
    if (focused) {
      const text = ' ' + rCell + mCell + pCell + tCell + bCell + (blurb + ' '.repeat(40)).slice(0, 30) + ' ';
      return <span className="row" key={role}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return [
      ['    ', null],
      [rCell, rMap[role]],
      [mCell, 'c-primary'],
      [pCell, 'c-accent'],
      [tCell, 'c-muted'],
      [bCell, 'c-muted'],
      [blurb, 'c-muted'],
    ];
  }
  const wrap = (v, k) => Array.isArray(v) ? window.row(v, W, k) : v;

  const heads = window.row([
    ['    ', null],
    [('role' + ' '.repeat(10)).slice(0, 10), 'c-label'],
    [('model' + ' '.repeat(26)).slice(0, 26), 'c-label'],
    [('prompt' + ' '.repeat(26)).slice(0, 26), 'c-label'],
    [('temp' + ' '.repeat(6)).slice(0, 6), 'c-label'],
    [('budget' + ' '.repeat(10)).slice(0, 10), 'c-label'],
    ['notes', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','15:19:00',[m(' /actor')], W, 'l1'),
    window.blankRow(W, 'b1'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'rule'),
    wrap(actor(false,'planner',  'openai:gpt-4.1',                  'sast.planner v4',           '0.2',  '$0.50',  'cheap, deterministic plans'), 'a'),
    wrap(actor(true ,'attacker', 'anthropic:claude-sonnet-4',       'sast.agentic.tracer v8',    '0.7',  '$2.50',  'aggressive · paranoid · cited'), 'b'),
    wrap(actor(false,'defender', 'openai:gpt-4.1',                  'carlini.defender v2',       '0.3',  '$0.50',  'critic · checks attacker plan'), 'c'),
    wrap(actor(false,'triager',  'openai:gpt-4.1-mini',             'sast.triager v3',           '0.1',  '$0.10',  'high precision dedupe'), 'd'),
    wrap(actor(false,'critic',   'google:gemini-2.5-pro (missing)', 'carlini.defender v2',       '0.3',  '$0.50',  'refusing — GOOGLE_API_KEY unset'), 'e'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('attacker · DETAIL', W, 's1'),
    window.row([T('   '), m('module overrides   '), p('sast → planner=openai:gpt-4.1   carlini → attacker=anthropic:opus-4.5')], W, 'd1'),
    window.row([T('   '), m('routing            '), p('direct'), m('  ·  '), m('parallel'), p(' off'), m('  ·  '), m('retry on '), p('rate-limit, 5xx')], W, 'd2'),
    window.row([T('   '), m('safety             '), m('refuse: '), p('exfil, real-net to non-allowlisted hosts')], W, 'd3'),
    window.row([T('   '), m('next               '), a('/actor attacker model anthropic:opus-4.5'), m('  ·  '), a('/actor attacker prompt sast.agentic.tracer v9.draft')], W, 'd4'),
    window.blankRow(W, 'b3'),
    window.logLine('agent','15:19:01',[
      m(' '), p('attacker'), m(' uses '), [' anthropic:claude-sonnet-4 ', 'c-warn'],
      m(' but the active key expires in '), [' 4d ', 'c-warn'], m('. '),
      a('/auth login anthropic'), m(' before the next long run.'),
    ], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /actor">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/actor · 4 active · 1 refusing', findings: 38,
        keybinds: [['j/k','row'],['m','model'],['p','prompt'],['t','temp']],
      })}
    </window.TermFrame>
  );
}
window.ActorView = ActorView;
