// /prompts — registered prompt templates with attribution and last-used.

function PromptsView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];

  function pr(focused, id, role, version, owner, last, blurb) {
    const rMap = { planner: 'c-label', attacker: 'c-danger', defender: 'c-success', triager: 'c-warn', generic: 'c-muted' };
    const idCell = (id + ' '.repeat(28)).slice(0, 26);
    const rCell  = (role + ' '.repeat(10)).slice(0, 10);
    const vCell  = (version + ' '.repeat(8)).slice(0, 6);
    const oCell  = (owner + ' '.repeat(12)).slice(0, 10);
    const lCell  = (last + ' '.repeat(10)).slice(0, 8);
    if (focused) {
      const text = ' ' + idCell + rCell + vCell + oCell + lCell + (blurb + ' '.repeat(60)).slice(0, 50) + ' ';
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return [
      ['    ', null],
      [idCell, 'c-accent'],
      [rCell, rMap[role]],
      [vCell, 'c-muted'],
      [oCell, 'c-muted'],
      [lCell, 'c-muted'],
      [blurb, 'c-primary'],
    ];
  }
  const wrap = (v, k) => Array.isArray(v) ? window.row(v, W, k) : v;

  const heads = window.row([
    ['    ', null],
    [('id' + ' '.repeat(26)).slice(0, 26), 'c-label'],
    [('role' + ' '.repeat(10)).slice(0, 10), 'c-label'],
    [('ver' + ' '.repeat(6)).slice(0, 6), 'c-label'],
    [('owner' + ' '.repeat(10)).slice(0, 10), 'c-label'],
    [('used' + ' '.repeat(8)).slice(0, 8), 'c-label'],
    ['blurb', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','15:14:00',[m(' /prompts')], W, 'l1'),
    window.blankRow(W, 'b1'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'r'),
    wrap(pr(false,'sast.planner',          'planner', 'v4',  'core',     '14:31', 'plan a sast umbrella run · prefer cheap-first'), 'a'),
    wrap(pr(true ,'sast.agentic.tracer',   'attacker','v8',  'core',     '14:33', 'taint trace via dataflow with budgets'), 'b'),
    wrap(pr(false,'sast.triager',          'triager', 'v3',  'core',     '14:34', 'classify raw hits into PROMOTE / DEDUPE / SUPPRESS'), 'c'),
    wrap(pr(false,'carlini.attacker',      'attacker','v2',  'core',     '13:38', 'paranoid offense · cite KB before action'), 'd'),
    wrap(pr(false,'carlini.defender',      'defender','v2',  'core',     '13:38', 'critique attacker plan · check for false-positives'), 'e'),
    wrap(pr(false,'threat-model.planner',  'planner', 'v3',  'core',     '13:21', 'STRIDE rollup over a workspace snapshot'), 'f'),
    wrap(pr(false,'verify.runner',         'generic', 'v2',  'core',     '13:51', 'reproduce a finding deterministically'), 'g'),
    wrap(pr(false,'patch.author',          'generic', 'v3',  'core',     '14:01', 'minimal-diff fix patch with tests'), 'h'),
    wrap(pr(false,'prompt-armor.attacker', 'attacker','v1',  'plugin',   '—',     'agent attack matrix probe'), 'i'),
    wrap(pr(false,'shinsa.auditor',        'generic', 'v1',  'plugin',   '—',     'iso 27001 / nist / soc2 control mapping'), 'j'),
    wrap(pr(false,'user.refund-bot.poc',   'attacker','v1',  'avi.k',    '13:38', 'project-local — synthesize refund-bot PoC'), 'k'),
    window.blankRow(W, 'b2'),
    window.logLine('flow','15:14:00',[
      m(' '), a('/prompt <id>'), m(' to view  ·  '), a('/tune <id>'), m(' to edit  ·  '), a('/actor <role>'), m(' to swap default'),
    ], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /prompts">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/prompts · 11 registered · 1 user', findings: 38,
        keybinds: [['j/k','row'],['enter','/prompt'],['t','/tune'],['a','/actor']],
      })}
    </window.TermFrame>
  );
}
window.PromptsView = PromptsView;
