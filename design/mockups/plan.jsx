// /plan — what the planner *would* do, before any tool runs. Dry-run.

function PlanView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function step(focused, n, mod, tool, est, gate, blurb) {
    const nCell = (n + ' '.repeat(6)).slice(0, 4);
    const mCell = (mod + ' '.repeat(20)).slice(0, 18);
    const tCell = (tool + ' '.repeat(28)).slice(0, 26);
    const eCell = (est + ' '.repeat(12)).slice(0, 10);
    const gMap = { auto: 'c-success', confirm: 'c-warn', refuse: 'c-danger' };
    if (focused) {
      const text = ' ' + nCell + mCell + tCell + eCell + (gate + ' '.repeat(10)).slice(0, 9)
        + (blurb + ' '.repeat(60)).slice(0, 50) + ' ';
      return <span className="row" key={n}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return [
      ['    ', null],
      [nCell, 'c-subtle'],
      [mCell, 'c-label'],
      [tCell, 'c-accent'],
      [eCell, 'c-muted'],
      [(gate + ' '.repeat(10)).slice(0, 9), gMap[gate]],
      [blurb, 'c-primary'],
    ];
  }
  const wrap = (v, k) => Array.isArray(v) ? window.row(v, W, k) : v;

  const lines = [
    window.logLine('in','15:21:00',[m(' /plan '), a('sast:scan'), m(' '), a('--budget 5.00 --since v1.2.0')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('goal      '), p('umbrella sast scan since '), p('v1.2.0'), m('  ·  scope '), p('apps/, libs/, jobs/')], W, 'h1'),
    window.row([T('  '), m('budget    '), p('$5.00'), m('  ·  '), m('est cost '), p('$1.74'), m('  ·  '), m('est wall '), p('~6m20s')], W, 'h2'),
    window.row([T('  '), m('routing   '), p('direct'), m('  ·  '), m('triage '), [' on ', 'c-success'], m('  ·  '), m('parallel '), [' off ', 'c-subtle')], W, 'h3'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('PLANNED STEPS · 9', W, 's1'),
    wrap(step(false,'1','context',     'context:read snapshot',          '0.0s · $0',   'auto',   'no rebuild required (fresh 3m ago)'), 'a'),
    wrap(step(false,'2','sast',        'tasks:resolve --since v1.2.0',   '0.4s · $0',   'auto',   'narrows scope to 312 changed files'), 'b'),
    wrap(step(false,'3','semgrep',     'semgrep:scan',                   '2.4s · $0',   'auto',   '612 rules, deterministic'), 'c'),
    wrap(step(false,'4','secret-scan', 'secret-scan:scan',               '0.8s · $0',   'auto',   '1284 candidates, regex set'), 'd'),
    wrap(step(true ,'5','agentic-sast','agentic-sast:scan h=2',          '~3m · $1.50', 'confirm','LLM dataflow + variant hunt — pricey'), 'e'),
    wrap(step(false,'6','triage',      'triage:run --input semgrep,*',   '~30s · $0.20','auto',   'classify into PROMOTE / DEDUPE / SUPPRESS'), 'f'),
    wrap(step(false,'7','sast',        'findings:emit',                  '0.1s · $0',   'auto',   'persist to .kuzushi/v2/findings.sqlite3'), 'g'),
    wrap(step(false,'8','sast',        'kb:cite-check',                  '0.2s · $0',   'auto',   'verify any KB citations resolve'), 'h'),
    wrap(step(false,'9','sast',        'codeql:scan',                    '—',           'refuse', 'codeql binary missing — skipped explicitly'), 'i'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('GUARDRAILS', W, 's2'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  step '), p('5'), m(' will pause for confirm — long-running, agentic, $1.50 estimated')], W, 'g1'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  step '), p('9'), m(' will refuse — '), p('codeql'), m(' binary not on $PATH (no fallback)')], W, 'g2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  est cost '), p('$1.74'), m(' under budget '), p('$5.00')], W, 'g3'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','15:21:01',[
      m(' approve with '), a('/run sast:scan'), m(' · adjust with '), a('/task block agentic-sast'),
      m(' · save plan with '), a('/plan write'),
    ], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /plan sast:scan --since v1.2.0">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'sast', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/plan · 9 steps · est $1.74 · ~6m20s', findings: 38,
        promptModule: 'sast',
        keybinds: [['enter','/run'],['/task','tweak'],['w','write plan'],['q','cancel']],
      })}
    </window.TermFrame>
  );
}
window.PlanView = PlanView;
