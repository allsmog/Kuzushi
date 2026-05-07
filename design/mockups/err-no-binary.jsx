// Error: no-binary. Refusing codeql when binary not on $PATH.

function ErrNoBinaryView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('in','13:58:02',[m(' /use '), a('codeql')], W, 'l1'),
    window.logLine('in','13:58:08',[m(' /run codeql:scan')], W, 'l2'),
    window.logLine('err','13:58:08',[
      m(' '), [' codeql:scan refused ', 'c-danger'], m(' · '), p('codeql'), m(' binary not found'),
    ], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('PROBE', W, 's1'),
    window.row([T('   '), m('which codeql           '), [' ✗ not found ', 'c-danger']], W, 'p1'),
    window.row([T('   '), m('CODEQL_HOME            '), m(' unset')], W, 'p2'),
    window.row([T('   '), m('config codeql.binary   '), m(' unset')], W, 'p3'),
    window.row([T('   '), m('~/.local/bin/codeql    '), [' ✗ no such file ', 'c-danger']], W, 'p4'),
    window.row([T('   '), m('~/codeql/codeql        '), [' ✗ no such file ', 'c-danger']], W, 'p5'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('FIX', W, 's2'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  install · '), a('brew install codeql'),
      m('  ·  or download from '), p('github.com/github/codeql-cli-binaries')], W, 'f1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('/run codeql:scan {"binary":"/opt/codeql/codeql"}'),
      m('   pass per-run')], W, 'f2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('/setg codeql.binary /opt/codeql/codeql'),
      m('   persist globally')], W, 'f3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), a('/task block codeql'),
      m('   keep it out of the umbrella entirely')], W, 'f4'),
    window.blankRow(W, 'b3'),
    window.row([T('  '), [' i ', 'c-accent'], m('  no fallback · kuzushi will not switch you to semgrep without your say-so')], W, 'i1'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','13:58:08',[m(' '), a('doctor'), m(' for full preflight')], W, 'l4'),
  ];

  return (
    <window.TermFrame title="kuzushi · codeql · NO BINARY">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'codeql', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'codeql · refused · binary missing', findings: 38,
        promptModule: 'codeql',
        keybinds: [['/setg','persist'],['/task block','skip'],['doctor','preflight'],['/back','catalog']],
      })}
    </window.TermFrame>
  );
}
window.ErrNoBinaryView = ErrNoBinaryView;
