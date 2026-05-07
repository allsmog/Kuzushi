// Auth view — /auth surface. Shows providers, credential status (no
// secrets), and active model selection.

function AuthView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  function provider(name, status, key, last, models) {
    const sg = status === 'connected' ? [' ✓ ', 'c-success']
              : status === 'expired' ? [' ! ', 'c-warn']
              : status === 'missing' ? [' ✗ ', 'c-danger']
              : [' · ', 'c-subtle'];
    return [
      [' ', null], sg, [' ', null],
      [(name + ' '.repeat(14)).slice(0, 12), 'c-accent'],
      [(status + '   ').slice(0, 11), status === 'connected' ? 'c-success' : status === 'expired' ? 'c-warn' : 'c-danger'],
      [(key + ' '.repeat(20)).slice(0, 18), 'c-primary'],
      [(last + ' '.repeat(20)).slice(0, 18), 'c-muted'],
      [models, 'c-muted'],
    ];
  }

  function modelRow(name, ctx, cost, default_) {
    return [
      [' ', null],
      [default_ ? '  ▌ ' : '    ', 'c-accent'],
      [(name + ' '.repeat(34)).slice(0, 32), default_ ? 'c-accent' : 'c-primary'],
      [('ctx ' + ctx + ' '.repeat(14)).slice(0, 14), 'c-muted'],
      [('$ ' + cost + ' '.repeat(20)).slice(0, 22), 'c-muted'],
      [default_ ? '· active' : '', 'c-success'],
    ];
  }

  const lines = [
    window.logLine('in',  '14:08:08', [m(' /auth')], W, 'l1'),
    window.blankRow(W, 'b1'),

    window.sectionHeader('PROVIDERS · 5', W, 'sec-p'),
    window.row(provider('openai',     'connected', 'sk-…vQ8R',     'last 2m ago',  'gpt-4.1, gpt-4o, o1, o3-mini'), W, 'p1'),
    window.row(provider('anthropic',  'connected', 'sk-ant-…pZ12', 'last 14h ago', 'claude-3.7-sonnet, claude-haiku'), W, 'p2'),
    window.row(provider('google',     'missing',   '—',            '—',             'gemini-2.5-pro, gemini-flash'), W, 'p3'),
    window.row(provider('github',     'expired',   'ghp_…m4Hs',    'expired 3d',    'used by /load gh:… and ndiff'), W, 'p4'),
    window.row(provider('local',      'connected', 'ollama@11434', 'last 1h ago',   'llama3.1:8b, qwen2.5-coder:32b'), W, 'p5'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('MODEL · effective', W, 'sec-m'),
    window.row([T('   '), m('current   '), p('openai:gpt-4.1'), m(' · context '), p('128k'), m(' · routing '), p('direct'), m(' · stop on missing key')], W, 'm0'),
    window.blankRow(W, 'b2b'),
    window.row(modelRow('openai:gpt-4.1',           '128k', '0.50/M in · 1.50/M out', true), W, 'm1'),
    window.row(modelRow('openai:gpt-4o',            '128k', '0.30/M in · 1.20/M out', false), W, 'm2'),
    window.row(modelRow('anthropic:claude-3.7-sonnet','200k','0.30/M in · 1.50/M out', false), W, 'm3'),
    window.row(modelRow('local:qwen2.5-coder:32b',  '32k',  'free (local)',           false), W, 'm4'),
    window.row([T('   '), m('   ▸ '), a('/model openai:gpt-4o'), m(' to switch · '), a('/backend list'), m(' to see routes · '), a('/cost'), m(' for spend')], W, 'm-cta'),
    window.blankRow(W, 'b3'),

    window.sectionHeader('SPEND · since 2026-05-01', W, 'sec-s'),
    window.row([T('   '), m('today     '), p('$ 1.42'), m('   · '), p('11 calls'), m('  · '), p('agentic-sast'), m(' + '), p('carlini'), m(' + '), p('threat-model'), m(' dominate')], W, 's1'),
    window.row([T('   '), m('this week '), p('$ 6.18'), m('   · '), p('budget '), p('$25'), m('  · '), p('25%')], W, 's2'),
    window.row([T('   '), m('this run  '), p('$ 0.00'), m('   · '), p('—')], W, 's3'),
    window.blankRow(W, 'b4'),

    window.logLine('log', '14:08:11', [m(' '), a('/auth login google'), m(' · '), a('/auth login github'), m(' · '), a('/auth rotate openai'), m('  (keychain · never echoed)')], W, 'l-end'),
  ];

  return (
    <window.TermFrame title="kuzushi · /auth · providers · model">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/auth · 3 connected · 1 expired · 1 missing', findings: 0,
        keybinds: [
          ['/auth', 'login <prov>'], ['/model', '<choice>'],
          ['/cost', 'spend'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.AuthView = AuthView;
