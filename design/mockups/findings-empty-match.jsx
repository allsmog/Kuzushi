// /findings empty match · "no rows match this filter"

function FindingsEmptyMatchView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function chip(label, on) {
    return [
      [' ', null],
      [' ' + label + ' ', on ? 'c-sel' : 'c-muted'],
      [' ', null],
    ];
  }

  const lines = [
    window.logLine('in','15:08:01',[m(' /findings '), a('--severity critical --module codeql --status fixed --since 24h')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([
      [' ', null],
      ['filter ', 'c-muted'],
      ...chip('CRITICAL', true), ...chip('high', false), ...chip('medium', false), ...chip('low', false),
      [' · ', 'c-subtle'],
      ...chip('module=codeql', true),
      [' · ', 'c-subtle'],
      ...chip('status=fixed', true),
      [' · ', 'c-subtle'],
      ...chip('since=24h', true),
    ], W, 'flt'),
    window.blankRow(W, 'b2'),
    window.row([T('  '), m('match '), p('0'), m(' / '), p('38')], W, 'h0'),
    window.blankRow(W, 'b3'),
    window.row([T('     '), ['∅  no findings match this filter', 'c-subtle']], W, 'g'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('WHY · most-likely', W, 's1'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('module=codeql'),
      m(' · codeql binary missing · 0 codeql runs in this workspace ever')], W, 'w1'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('status=fixed'),
      m(' · 0 fixed in last 24h · 0 fixed total (only F-0007 was patched, and that\'s "patched" not "fixed")')], W, 'w2'),
    window.row([T('   '), [' · ', 'c-subtle'], m('  '), p('severity=CRITICAL'),
      m(' · 3 CRITICALs exist (F-0001, F-0002, F-0012) · all in last 6h')], W, 'w3'),
    window.blankRow(W, 'b5'),
    window.sectionHeader('LOOSEN', W, 's2'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('/findings --severity CRITICAL --since 24h'),
      m('             matches '), p('3')], W, 'l1a'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('/findings --severity high+ --status fixed,verified'),
      m('   matches '), p('2')], W, 'l2a'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('/findings --module codeql --since all'),
      m('                  matches '), p('0'), m('  ('), a('install codeql first'), m(')')], W, 'l3a'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), a('/findings'),
      m('                                          matches '), p('38')], W, 'l4a'),
    window.blankRow(W, 'b6'),
    window.logLine('flow','15:08:01',[m(' '), [' tip ', 'c-warn'],
      m(' '), p('--module codeql'), m(' implies "from a codeql run" · semgrep findings about CodeQL classes need '),
      a('--cwe'), m(' / '), a('--rule'), m(' instead')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /findings · 0 match">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'findings', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'findings · 0 of 38 match', findings: 38,
        promptModule: 'findings',
        keybinds: [['Esc','clear'],['/findings','reset'],['enter','use suggestion']],
      })}
    </window.TermFrame>
  );
}
window.FindingsEmptyMatchView = FindingsEmptyMatchView;
