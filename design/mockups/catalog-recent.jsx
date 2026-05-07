// catalog · with recent runs + active jobs overlay

function CatalogRecentView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function modRow(state, id, mark, desc) {
    const sMap = {
      idle:    [' · ', 'c-subtle'],
      run:     [' ⏵ ', 'c-warn'],
      done:    [' ✓ ', 'c-success'],
      flag:    [' ▸ ', 'c-warn'],
      paused:  [' ‖ ', 'c-warn'],
    };
    const idCell = (id + ' '.repeat(28)).slice(0, 22);
    const mCell  = (mark + ' '.repeat(28)).slice(0, 24);
    const dCell  = desc;
    return [
      [' ', null], sMap[state],
      [idCell, 'c-primary'],
      [mCell, state === 'run' ? 'c-warn' : state === 'flag' ? 'c-warn' : state === 'done' ? 'c-success' : 'c-muted'],
      [dCell, 'c-muted'],
    ];
  }

  function head(name, blurb) {
    return window.row([
      [' ', null],
      [`── ${name} `, 'c-label'],
      [`${blurb} `, 'c-muted'],
      ['─'.repeat(Math.max(0, W - 1 - 4 - name.length - 1 - blurb.length - 1)), 'c-subtle'],
    ], W, name);
  }

  const lines = [
    window.row([T(' '), m('active '), p('2'), m('  ·  '), m('today '), p('14 runs · 38 findings · $6.84'),
      m('  ·  '), m('queue '), p('1'), m('  ·  '), m('budget '), p('$18.16 left')], W, 'h0'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('ACTIVE NOW', W, 's0'),
    window.row(modRow('run',   'agentic-sast',     '⏵ r-2118 · frame 41/64',  'budget hard-stop · resume?'),  W, 'an1'),
    window.row(modRow('run',   'verify',           '⏵ r-2117 · stage 6/10',    'F-0027 sandbox spinning'),     W, 'an2'),
    window.row(modRow('paused','triage',           '‖ r-2119 · 7 pending',      'paused for budget reason'),    W, 'an3'),
    window.blankRow(W, 'b2'),
    head('OFFENSE', 'find vulnerabilities by scanning code, deps, and runtime surface'),
    window.row(modRow('done',  'sast',             '✓ 11 hits · 14:33',        'umbrella · semgrep+secrets+agentic'), W, 'o1'),
    window.row(modRow('done',  'semgrep',          '✓ 18 raw · 11 triaged',    'pattern SAST'),                       W, 'o2'),
    window.row(modRow('idle',  'codeql',           '— · binary missing',        'install codeql first'),               W, 'o3'),
    window.row(modRow('flag',  'agentic-sast',     '▸ F-0012 CRITICAL',         'in flight · $2.50 hard stop'),         W, 'o4'),
    window.row(modRow('flag',  'carlini',          '▸ F-0012 (h2)',             'last 27m · $1.41'),                    W, 'o5'),
    window.row(modRow('done',  'secret-scan',      '✓ 3 hits · 1 active',       'aws-key live in .env.example'),         W, 'o6'),
    window.row(modRow('done',  'iac-scan',         '✓ 14 hits · 2 crit',         'k8s root + s3 public'),                 W, 'o7'),
    window.row(modRow('done',  'dep-hygiene',      '✓ 41 stale · 6 kev',        'plan: 6 critical now'),                 W, 'o8'),
    window.blankRow(W, 'b3'),
    head('INTEL', 'context · recon · threat-model · ndiff · kb'),
    window.row(modRow('done',  'context',          '✓ 482 files indexed',       'fresh as of 14:32'),                    W, 'i1'),
    window.row(modRow('done',  'threat-model',     '✓ v3 · pre-v2 diff staged',  'PR412 forced reranking'),               W, 'i2'),
    window.row(modRow('done',  'kb',               '✓ pulled · 41 new',          'CVE-2026-2941 + CVE-2026-2877 affect'), W, 'i3'),
    window.row(modRow('idle',  'recon',            '— · last 5d ago',            'targets: refund.acme + stage'),         W, 'i4'),
    window.row(modRow('done',  'ndiff',            '✓ 3 candidates ready',       'CVE-2026-2941 · 0/3 verified'),         W, 'i5'),
    window.blankRow(W, 'b4'),
    head('DEFENSE', 'triage · verify · patch · findings · snapshot'),
    window.row(modRow('flag',  'triage',           '▸ 7 pending · F-0012',       'queue moving · 22/hr'),                 W, 'd1'),
    window.row(modRow('run',   'verify',           '⏵ F-0027 sandbox',           'stage 6/10 · ts api stub'),             W, 'd2'),
    window.row(modRow('done',  'patch',            '✓ F-0002 fixed',             'F-0012 same shape · ~ 5 min'),          W, 'd3'),
    window.row(modRow('idle',  'findings',         '— · 38 open',                'k high · 3 crit · 12 med · 13 low'),    W, 'd4'),
    window.row(modRow('idle',  'snapshot',         '— · 14 snapshots · 41 MB',   'auto + 5 manual'),                       W, 'd5'),
    window.blankRow(W, 'b5'),
    head('NEXT', 'recommended by router'),
    window.row([T('  '), [' ▸ 1 ', 'c-warn'], a('/use patch F-0012'),
      m('       same fix shape as F-0002 · staged · ~ 5 min')], W, 'n1'),
    window.row([T('  '), [' ▸ 2 ', 'c-warn'], a('/use verify F-0034'),
      m('     k8s root · sandbox kustomize render')], W, 'n2'),
    window.row([T('  '), [' ▸ 3 ', 'c-warn'], a('/run dep-hygiene --apply 1..2'),
      m('  postgres-rs + curl · kev'),  m(' · '), m('first')], W, 'n3'),
    window.row([T('  '), [' ▸ 4 ', 'c-warn'], a('/story --audience triage'),
      m('   memo summarizing today for jen.t before standup')], W, 'n4'),
  ];

  return (
    <window.TermFrame title="kuzushi · catalog · recent + active overlay">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$6.84' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'idle · 2 active · 1 paused · routing direct', findings: 38,
        keybinds: [['j/k','row'],['a','attach run'],['1..4','next'],['/runs','queue'],['?','help']],
      })}
    </window.TermFrame>
  );
}
window.CatalogRecentView = CatalogRecentView;
