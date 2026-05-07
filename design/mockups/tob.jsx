// Trail of Bits audit skills view — curated audit playbooks the operator
// runs against the codebase. Each "skill" emits qualitative findings.

function TobView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  function skill(name, verdict, blurb) {
    const verdictColor = verdict === 'CLEAN' ? 'c-success'
      : verdict === 'ISSUES' ? 'c-danger'
      : verdict === 'NOTES' ? 'c-warn' : 'c-muted';
    return [
      [' ', null],
      [(name + ' '.repeat(36)).slice(0, 32), 'c-accent'],
      [(verdict + '   ').slice(0, 8), verdictColor],
      [blurb, 'c-primary'],
    ];
  }

  function note(sev, name, where) {
    const sevMap = { critical: 'c-sev-critical', high: 'c-sev-high', medium: 'c-sev-medium', low: 'c-sev-low' };
    return [
      [' ', null],
      [(sev.toUpperCase() + ' '.repeat(10)).slice(0, 9), sevMap[sev]],
      [(name + ' '.repeat(60)).slice(0, 52), 'c-primary'],
      [where, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in', '15:21:02', [m(' /use '), a('tob')], W, 'l1'),
    window.logLine('in', '15:21:09', [m(' /show '), a('skills')], W, 'l2'),
    window.logLine('ok', '15:21:09', [m(' 12 audit skills available · cached at '), p('~/.kuzushi/skills/tob@v1.4'), m(' (signed)')], W, 'l3'),
    window.blankRow(W, 'b1'),

    window.sectionHeader('SKILLS · 12 audit playbooks', W, 'sec-sk'),
    window.row(skill('rust-unsafe-audit',         'NOTES',  '14 unsafe blocks · 2 lack invariants doc'), W, 'sk1'),
    window.row(skill('crypto-misuse',             'ISSUES', 'jwt alg=none path · cbc without hmac in legacy'), W, 'sk2'),
    window.row(skill('webapp-auth-bypass',        'ISSUES', 'admin subdomain shares jwt secret · F-0003'), W, 'sk3'),
    window.row(skill('webhook-replay',            'ISSUES', 'stripe handler accepts staging signatures'), W, 'sk4'),
    window.row(skill('llm-prompt-injection',      'ISSUES', 'concierge + refund-bot reach tainted sinks'), W, 'sk5'),
    window.row(skill('llm-tool-confused-deputy',  'NOTES',  'lookup_order returns into system msg · review'), W, 'sk6'),
    window.row(skill('amqp-message-integrity',    'NOTES',  'worker pool reads unsigned envelopes'), W, 'sk7'),
    window.row(skill('iam-least-privilege',       'CLEAN',  'reviewed 14 roles · scoped to resources'), W, 'sk8'),
    window.row(skill('container-escape-surface',  'CLEAN',  'no /proc, /sys mounts · seccomp default'), W, 'sk9'),
    window.row(skill('supply-chain-typosquat',    'CLEAN',  '184 deps · 0 lookalike names found'), W, 'sk10'),
    window.row(skill('build-reproducibility',     'NOTES',  'rust target/ ok · ts dist/ has timestamps'), W, 'sk11'),
    window.row(skill('telemetry-data-leakage',    'CLEAN',  'no PII in metric labels or trace tags'), W, 'sk12'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('NOTES FROM "llm-prompt-injection" · run inline', W, 'sec-notes'),
    window.row(note('critical', 'concierge agent splices review.body into system prompt',  'apps/web/agents/concierge.ts:88'), W, 'n1'),
    window.row(note('critical', 'refund-bot concats ticket.subject into role:system',       'apps/web/agents/refund-bot.ts:127'), W, 'n2'),
    window.row(note('high',     'second-order via order.notes through lookup_order tool',   'apps/web/agents/concierge.ts:241'), W, 'n3'),
    window.row(note('medium',   'no allow-list for tools the model may invoke',             'apps/web/agents/runner.ts:54'), W, 'n4'),
    window.row(note('low',      'agent message log writes raw user text to stdout',         'apps/web/agents/runner.ts:88'), W, 'n5'),
    window.blankRow(W, 'b3'),

    window.logLine('agent', '15:21:31', [
      m(' the four "ISSUES" skills overlap on '), a('admin.acme-checkout.com'), m(' — patch its jwt boundary first.'),
    ], W, 'l-end'),
    window.logLine('log', '15:21:31', [m(' run a skill: '), a('/run llm-prompt-injection'), m('  ·  promote: '), a('/promote n1 n2 --severity critical')], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · tob · audit skills">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'tob', cost: '$0.14' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'tob · 12 skills · 5 with issues', findings: 5,
        promptModule: 'tob',
        keybinds: [
          ['/run', '<skill>'], ['/promote', 'n1 n2'],
          ['/show', 'skill <name>'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.TobView = TobView;
