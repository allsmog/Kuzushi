// command palette · Ctrl-P · fuzzy

function CommandPaletteView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function pal(focused, cmd, ctx, hint) {
    const cCell = (cmd + ' '.repeat(34)).slice(0, 30);
    const xCell = (ctx + ' '.repeat(20)).slice(0, 16);
    const hCell = hint;
    if (focused) {
      const text = ' ' + cCell + xCell + hCell;
      return <span className="row" key={cmd}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [cCell, 'c-primary'],
      [xCell, 'c-muted'],
      [hCell, 'c-muted'],
    ], W, cmd);
  }

  const lines = [
    window.logLine('in','16:02:01',[m(' Ctrl-P')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), p(' › '),
      [' patch f', 'c-primary'],
      [' ', null],
      [' '.repeat(W - 14), null],
    ], W, 'q1'),
    window.row([T('  '), m('matches '), p('14'),
      m('  ·  '), m('shown '), p('10'),
      m('  ·  '), m('source '), p('built-ins · plugins · history')], W, 'q2'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('EXACT', W, 's1'),
    pal(true,  '/use patch F-0012',           'finding · open',          'critical · refund-bot.ts:127 · same shape as F-0002'),
    pal(false, '/use patch F-0027',           'finding · verifying',     'high · concierge → orca-llm SSRF chain'),
    pal(false, '/use patch F-0034',           'finding · open',          'critical · k8s root + privileged · class-fix avail'),
    pal(false, '/use patch S-01',             'secret · active',         'aws-access-key · history rewrite + .env scrub'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('FUZZY', W, 's2'),
    pal(false, '/show patch r-2115',          'run · 14:38',             'concierge.ts patch · already applied'),
    pal(false, '/findings filter --status patched', 'findings · scope',    '4 entries · last 24h'),
    pal(false, '/use patch postgres-rs --pin 0.7.24', 'dep · upgrade-plan', 'CVE-2026-2941 · staged'),
    pal(false, '/options patch',              'config · current',        'show options for the patch module'),
    pal(false, '/run patch --apply-class F-0034', 'iac · class-fix',      'fixes F-0034, F-0035, F-0039 in one staged patch'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('FROM HISTORY · today', W, 's3'),
    pal(false, '/use patch F-0002',           'history · 15:22',         'CRITICAL prompt-inj · concierge.ts · ✓ applied'),
    window.blankRow(W, 'b5'),
    window.sectionHeader('ACTIONS', W, 's4'),
    window.row([T('   '), m('   '), a('enter'),  m(' run · '),
      a('Ctrl-V'), m(' edit before run · '),
      a('Tab'), m(' complete · '),
      a('Esc'), m(' close · '),
      a('? '), m('open help for this command')], W, 'a1'),
    window.row([T('   '), m('   '), m('palette is scope-aware · the "ctx" column tells you where the suggestion comes from')], W, 'a2'),
    window.blankRow(W, 'b6'),
    window.sectionHeader('TIPS', W, 's5'),
    window.row([T('   '), m('   '), p('@ '),  m('prefix to filter only findings'),
      m('   ·   '), p('# '), m('only kb refs'),
      m('   ·   '), p('$ '), m('only options'),
      m('   ·   '), p('. '), m('only files in workspace')], W, 't1'),
    window.row([T('   '), m('   '), p('!'),   m(' before a command runs without confirm '),
      m('(refused for write/destructive)')], W, 't2'),
    window.row([T('   '), m('   '), p('=>'),  m(' pipes one suggestion into another · e.g. '),
      a('@F-0012 => /use patch'),  m(' = same as the first row above')], W, 't3'),
  ];

  return (
    <window.TermFrame title="kuzushi · Ctrl-P · palette">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'palette', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'palette · "patch f" · 14 matches', findings: 38,
        promptModule: 'palette',
        keybinds: [['j/k','match'],['enter','run'],['Ctrl-V','edit'],['Esc','close']],
      })}
    </window.TermFrame>
  );
}
window.CommandPaletteView = CommandPaletteView;
