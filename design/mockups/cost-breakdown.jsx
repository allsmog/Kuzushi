// /cost · per-actor breakdown

function CostBreakdownView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function row(actor, model, calls, tin, tout, usd, share) {
    const w = 14;
    const filled = Math.round(w * share);
    return [
      [' ', null],
      [(actor + ' '.repeat(14)).slice(0, 12), 'c-accent'],
      [(model + ' '.repeat(36)).slice(0, 32), 'c-primary'],
      [(String(calls) + ' '.repeat(8)).slice(0, 6), 'c-muted'],
      [(tin + ' '.repeat(12)).slice(0, 10), 'c-muted'],
      [(tout + ' '.repeat(12)).slice(0, 10), 'c-muted'],
      [('$' + usd + ' '.repeat(14)).slice(0, 10), 'c-primary'],
      ['[', 'c-subtle'],
      ['█'.repeat(filled), 'c-success'],
      ['░'.repeat(w - filled), 'c-subtle'],
      ['] ', 'c-subtle'],
      [(Math.round(share * 100) + '%' + '   ').slice(0, 5), 'c-muted'],
    ];
  }

  const heads = window.row([
    [' ', null],
    [('actor' + ' '.repeat(12)).slice(0, 12), 'c-label'],
    [('model' + ' '.repeat(32)).slice(0, 32), 'c-label'],
    [('calls' + ' '.repeat(6)).slice(0, 6), 'c-label'],
    [('in' + ' '.repeat(10)).slice(0, 10), 'c-label'],
    [('out' + ' '.repeat(10)).slice(0, 10), 'c-label'],
    [('$' + ' '.repeat(10)).slice(0, 10), 'c-label'],
    ['share', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','15:02:01',[m(' /cost '), a('--by actor --since week')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('total '), p('$ 6.18'),
      m('   budget '), p('$ 25.00'),
      m('   remaining '), p('$ 18.82'),
      m('   resets '), p('Mon 00:00 UTC')], W, 'h0'),
    window.blankRow(W, 'b2'),
    heads,
    window.row([[' ', null], ['─'.repeat(W - 2), 'c-subtle']], W, 'r'),
    window.row(row('attacker',  'anthropic:claude-sonnet-4',  248, '2.41M', '184k',  '3.18',  0.51), W, 'a1'),
    window.row(row('planner',   'openai:gpt-4.1',              82, '0.62M',  '88k',  '0.92',  0.15), W, 'a2'),
    window.row(row('patcher',   'anthropic:claude-sonnet-4',   41, '0.41M',  '52k',  '0.78',  0.13), W, 'a3'),
    window.row(row('triager',   'openai:gpt-4.1-mini',        612, '1.18M', '142k',  '0.61',  0.10), W, 'a4'),
    window.row(row('defender',  'openai:gpt-4.1',              94, '0.41M',  '38k',  '0.42',  0.07), W, 'a5'),
    window.row(row('verifier',  'openai:gpt-4.1',              22, '0.18M',  '12k',  '0.18',  0.03), W, 'a6'),
    window.row(row('narrator',  'anthropic:claude-haiku',      18, '0.21M',  '14k',  '0.07',  0.01), W, 'a7'),
    window.row(row('redteam',   '— · default attacker',         0, '—',     '—',    '0.00',  0.00), W, 'a8'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('TOP MODULES · drives the spend', W, 's1'),
    window.row([T('   '), p('agentic-sast'),  m('   $2.18  '), p('+58 mins'),  m('   '), p('128 calls'),  m('   F-0019, F-0027, F-0034')], W, 'tm1'),
    window.row([T('   '), p('carlini'),       m('        $1.41  '), p('+27 mins'),  m('   '), p('148 calls'),  m('   F-0012')], W, 'tm2'),
    window.row([T('   '), p('threat-model'),  m('   $0.92  '), p('+18 mins'),  m('   '), p('14 calls'),   m('   v3 model')], W, 'tm3'),
    window.row([T('   '), p('patch'),          m('          $0.78  '), p('+11 mins'),  m('   '), p('41 calls'),   m('   F-0002, F-0007')], W, 'tm4'),
    window.row([T('   '), p('triage'),         m('         $0.61  '), p('+22 mins'),  m('   '), p('612 calls'),  m('   high-volume classify')], W, 'tm5'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','15:02:01',[m(' '), a('/cost --by module'),
      m(' · '), a('--by day'), m(' · '), a('--by run'), m(' · '), a('--csv > /tmp/spend.csv')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /cost · by actor · this week">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'cost', cost: '$6.18' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'cost · 8 actors · 7d · $6.18 / $25', findings: 38,
        promptModule: 'cost',
        keybinds: [['--by','actor|module|day'],['--csv','export'],['/budget','set']],
      })}
    </window.TermFrame>
  );
}
window.CostBreakdownView = CostBreakdownView;
