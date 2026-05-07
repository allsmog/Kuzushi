// /actor list + bind + swap. 8-role binding surface.

function ActorBindView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function role(focused, name, model, ctx, cost, used) {
    const idCell  = (name + ' '.repeat(20)).slice(0, 14);
    const mCell   = (model + ' '.repeat(34)).slice(0, 30);
    const cCell   = (ctx + ' '.repeat(8)).slice(0, 6);
    const $Cell   = ('$' + cost + ' '.repeat(18)).slice(0, 16);
    const uCell   = (used + ' '.repeat(40)).slice(0, 36);
    if (focused) {
      const text = ' ' + idCell + mCell + cCell + $Cell + uCell;
      return <span className="row" key={name}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [idCell, 'c-accent'],
      [mCell, 'c-primary'],
      [cCell, 'c-muted'],
      [$Cell, 'c-muted'],
      [uCell, 'c-muted'],
    ], W, name);
  }

  const heads = window.row([
    ['    ', null],
    [('role' + ' '.repeat(14)).slice(0, 14), 'c-label'],
    [('model' + ' '.repeat(30)).slice(0, 30), 'c-label'],
    [('ctx' + ' '.repeat(6)).slice(0, 6), 'c-label'],
    [('per-MTok' + ' '.repeat(16)).slice(0, 16), 'c-label'],
    ['used by', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','14:18:01',[m(' /actor')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('8 roles · '), p('5'), m(' bound · '), p('3'), m(' default · session refusal rate '), p('4%')], W, 'h0'),
    window.blankRow(W, 'b2'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'rule'),
    role(false, 'planner',    'openai:gpt-4.1',                  '128k', '0.50/in 1.50/out', '/plan, /story, threat-model'),
    role(true,  'attacker',   'anthropic:claude-sonnet-4',       '200k', '0.30/in 1.50/out', 'carlini, agentic-sast, randori'),
    role(false, 'defender',   'openai:gpt-4.1',                  '128k', '0.50/in 1.50/out', 'triage critic, post-scan defender'),
    role(false, 'triager',    'openai:gpt-4.1-mini',             '128k', '0.10/in 0.30/out', 'high-volume classify'),
    role(false, 'patcher',    'anthropic:claude-sonnet-4',       '200k', '0.30/in 1.50/out', 'patch:run drafts'),
    role(false, 'verifier',   'openai:gpt-4.1',                  '128k', '0.50/in 1.50/out', 'verify rerun, PoC re-emit'),
    role(false, 'narrator',   'anthropic:claude-haiku',          '200k', '0.08/in 0.40/out', '/story, deep-auditor narrative'),
    role(false, 'redteam',    '— · default to attacker',         '—',    '—',                'fallback'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('TRANSCRIPT · last 10 dispatches', W, 's2'),
    window.row([T('   '), m('14:17:22  '), p('attacker'),  m('  → '), p('sandbox:run curl'),         m('   '), [' agent ', 'c-label']], W, 't1'),
    window.row([T('   '), m('14:17:18  '), p('triager'),   m('   → '), p('classify F-0027..F-0031'),  m('  '), [' batch ', 'c-accent']], W, 't2'),
    window.row([T('   '), m('14:16:54  '), p('attacker'),  m('  → '), p('write_patch_attempt'),       m('  '), [' refused ', 'c-danger']], W, 't3'),
    window.row([T('   '), m('14:16:11  '), p('planner'),   m('   → '), p('plan(F-0002, h=2)'),        m('       '), [' agent ', 'c-label']], W, 't4'),
    window.row([T('   '), m('14:15:42  '), p('defender'),  m('  → '), p('critic(F-0006)'),            m('         '), [' agent ', 'c-label']], W, 't5'),
    window.blankRow(W, 'b4'),
    window.logLine('in','14:18:30',[m(' /actor patcher model anthropic:opus-4.5')], W, 'l2'),
    window.logLine('ok','14:18:30',[m(' rebound '), p('patcher'), m(' → '), p('anthropic:opus-4.5'), m(' · written to '), p('~/.kuzushi/v2/actors.toml')], W, 'l3'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','14:18:30',[m(' '), a('/actor swap planner attacker'), m('  to swap two roles for one run')], W, 'l4'),
  ];

  return (
    <window.TermFrame title="kuzushi · /actor · 8-role binding">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'actor', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'actors · 5 bound · 3 default', findings: 38,
        promptModule: 'actor',
        keybinds: [['j/k','row'],['enter','rebind'],['/actor swap','two roles'],['/actor reset','defaults']],
      })}
    </window.TermFrame>
  );
}
window.ActorBindView = ActorBindView;
