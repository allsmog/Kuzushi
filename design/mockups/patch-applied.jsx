// patch · applied state (post-apply, post-verify)

function PatchAppliedView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('in','15:22:01',[m(' a')], W, 'l1'),
    window.logLine('run','15:22:01',[m(' apply F-0002 · 1 file · 1 hunk · '),
      [' resolved ', 'c-success'], m(' (three-way · merged with redactPII)')], W, 'l2'),
    window.logLine('ok','15:22:02',[m(' wrote '), p('apps/web/agents/concierge.ts'), m(' · '),
      p('+8 / -2'), m(' · audit '), p('audit.log:1842')], W, 'l3'),
    window.logLine('ok','15:22:02',[m(' new test '), p('concierge.test.ts'),
      m(' · '), p('+4'), m(' · audit '), p('audit.log:1843')], W, 'l4'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('POST-APPLY CHECKS', W, 's1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('typecheck'),    m('   tsc --noEmit · 0 errors')], W, 'c1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('test (suite)'), m('  62 / 62 pass · 4.0s')], W, 'c2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('test (new)'),   m('     1 / 1 pass · "review.body cannot override sysprompt"')], W, 'c3'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('lint'),         m('         clean')], W, 'c4'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('verify rerun'), m('  '), p('PoC 15:22-redo'),
      m(' · model now reports '), [' negative ', 'c-success'], m(' for ATT&CK T1059')], W, 'c5'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('LEDGER', W, 's2'),
    window.row([T('   '), m('F-0002 status   '), p('open → triaging → patched → verified-fixed'), m('  ('),
      p('audit.log:1844'), m(')')], W, 'sl1'),
    window.row([T('   '), m('linked runs     '), p('r-2113'), m(' (hunt)  '), p('r-2115'),
      m(' (patch)  '), p('r-2117'), m(' (verify-rerun)')], W, 'sl2'),
    window.row([T('   '), m('linked finding  '), p('F-0012'), m(' shares fix shape · '),
      [' propose patch? ', 'c-warn']], W, 'sl3'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('GIT', W, 's3'),
    window.row([T('   '), m('worktree   '), p('.kuzushi/worktree-r2115/'), m('  ·  '),
      m('upstream  '), p('main'), m(' (clean as of 14:32)')], W, 'g1'),
    window.row([T('   '), m('proposed   '), p('feat: tag review.body as user-turn (fixes F-0002)'),
      m('  ·  '), p('+8 / -2'), m(' · '), p('1 test')], W, 'g2'),
    window.row([T('   '), [' c ', 'c-accent'], m('  commit  '), [' p ', 'c-accent'], m('  push '),
      [' P ', 'c-accent'], m('  open PR (gh)  '), [' r ', 'c-accent'], m('  revert (uses snapshot)')], W, 'g3'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('NEXT', W, 's4'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('/use patch F-0012'),
      m('       same fix shape applies to refund-bot ($-loss)')], W, 'n1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('/use threat-model --note F-0002 closed'),
      m('   reduce risk rank for prompt-injection class')], W, 'n2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('/story --since this-run'),
      m('         dictate the patch memo for review')], W, 'n3'),
    window.blankRow(W, 'b5'),
    window.logLine('agent','15:22:08',[
      m(' '), [' fixed ', 'c-success'],
      m(' F-0002 · same fix shape on F-0012 takes ~5 min · suggest staying on the patcher'),
    ], W, 'l5'),
  ];

  return (
    <window.TermFrame title="kuzushi · patch · APPLIED · F-0002">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'patch', cost: '$0.21' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'patch · F-0002 verified-fixed · checks 5/5', findings: 38,
        promptModule: 'patch',
        keybinds: [['c','commit'],['p','push'],['P','open PR'],['/use patch F-0012','next']],
      })}
    </window.TermFrame>
  );
}
window.PatchAppliedView = PatchAppliedView;
