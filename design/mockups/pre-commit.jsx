// pre-commit · kuzushi pre-commit · git hook running

function PreCommitView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('in','17:58:01',[m(' $ git commit -m "fix refund partial flow" ')], W, 'l1'),
    window.logLine('in','17:58:01',[m(' .git/hooks/pre-commit → kuzushi pre-commit ')], W, 'l2'),
    window.row([T('  '), m('staged · '), p('3 files · 142 added · 18 removed'), m(' · scope-limited to '), p('the diff'), m(' · '),
      a('budget $0.05 / 30s')], W, 'h0'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('CHECKS · pre-commit · staged diff only', W, 's1'),
    window.row([T('   '), [' ✓ ', 'c-success'], p(' secrets        '), m('   3 files · 0 hits                 '), [' 0.31s ', 'c-subtle']], W, 'c1'),
    window.row([T('   '), [' ✓ ', 'c-success'], p(' lint           '), m('   3 files · 0 hits                 '), [' 0.18s ', 'c-subtle']], W, 'c2'),
    window.row([T('   '), [' ⏵ ', 'c-primary'], p(' semgrep        '), m('   3 files · scanning ['),
      [' ████████████████░░░░ ', 'c-accent'], m(' 80% ] '), [' 1.4s  ', 'c-subtle']], W, 'c3'),
    window.row([T('   '), [' · ', 'c-subtle'], p(' agentic-sast   '), m('   queued · only if semgrep finds something '), [' —     ', 'c-subtle']], W, 'c4'),
    window.row([T('   '), [' · ', 'c-subtle'], p(' verify         '), m('   queued                              '), [' —     ', 'c-subtle']], W, 'c5'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('NEW HIT · semgrep · refund-bot.ts:127', W, 's2'),
    window.row([T('   '), [' ⚠ ', 'c-warn'],
      [' MED ', 'c-sev-medium'], m(' '), p('refund-bot.ts:127 '),
      m('· '), a('user-controlled-url-in-fetch')], W, 'h1'),
    window.row([T('   '), m('  '), m('  '), p('         > '), a('await fetch(req.body.callback_url)')], W, 'h2'),
    window.row([T('   '), m('  '), m('  '), p('         > '), m('rule '), a('javascript.lang.security.ssrf-fetch')], W, 'h3'),
    window.row([T('   '), m('  '), m('  '), p('         > '), m('the agent will hunt for variants if you '), a('pass through'), m(' with '), p('--scan')], W, 'h4'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('DECISION', W, 's3'),
    window.row([T('   '), m('  '), [' ⛔ ', 'c-danger'], p(' BLOCKED'),
      m('     this commit · 1 MED hit (config '), a('block-on: med+'), m(')')], W, 'd1'),
    window.row([T('   '), m('       '), p('options ')], W, 'd2'),
    window.row([T('   '), m('         '), a('y'), m(' deepen ('), a('+ agentic-sast'), m(' on this hunk · '), a('~30s'), m(' · '), a('$0.04'), m(')')], W, 'd3'),
    window.row([T('   '), m('         '), a('p'), m(' patch  ('), p('agent suggests an allowlist'),  m(' · staged for review)')], W, 'd4'),
    window.row([T('   '), m('         '), a('s'), m(' suppress ('), p('add #kuzushi:ignore on this line · logged'), m(')')], W, 'd5'),
    window.row([T('   '), m('         '), a('!'), m(' bypass  ('), [' --no-verify ', 'c-warn'], m(' · still recorded to ledger)')], W, 'd6'),
    window.blankRow(W, 'b4'),
    window.row([T('   '), m('   '), m('every commit · with or without bypass · is appended to '), p('.kuzushi/precommit.log')], W, 'tip'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','17:58:14',[m(' '), a('y'), m(' deepen · '),
      a('p'), m(' patch · '),
      a('s'), m(' suppress · '),
      a('!'), m(' bypass · '),
      a('Esc'), m(' abort commit')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · pre-commit · 1 hit · BLOCKED">
      {window.statusStrip({ target: '~/work/acme-checkout (staged)', ctx: '3 files', module: 'pre-commit', cost: '$0.01' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'pre-commit · 1 MED hit · BLOCKED · awaiting decision',
        findings: 1,
        promptModule: 'pre-commit',
        keybinds: [['y','deepen'],['p','patch'],['s','suppress'],['!','bypass'],['Esc','abort']],
      })}
    </window.TermFrame>
  );
}
window.PreCommitView = PreCommitView;
