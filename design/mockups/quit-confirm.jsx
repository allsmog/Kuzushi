// /quit confirm with dirty work

function QuitConfirmView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('in','15:59:14',[m(' Ctrl-C  ·  /quit')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ['╔══ DON\'T LEAVE WORK BEHIND ', 'c-warn'],
      ['═'.repeat(W - 4 - 28 - 1), 'c-warn'], ['╗', 'c-warn']], W, 'top'),
    window.row([T('   '), ['║ ', 'c-warn'],
      [' you have 3 things in flight that will end the moment kuzushi exits'.padEnd(W - 8, ' '), 'c-primary'],
      [' ║', 'c-warn']], W, 'r1'),
    window.row([T('   '), ['╚', 'c-warn'], ['═'.repeat(W - 6), 'c-warn'], ['╝', 'c-warn']], W, 'bot'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('IN FLIGHT · will be checkpointed if you confirm', W, 's1'),
    window.row([T('   '), [' ⏵ ', 'c-warn'], m('  '), p('agentic-sast'),
      m('   r-2118 · '), p('frame 41/64'),  m(' · paused on budget'),
      m(' · '), [' resumable ', 'c-success']], W, 'i1'),
    window.row([T('   '), [' ⏵ ', 'c-warn'], m('  '), p('verify'),
      m('         r-2117 · '), p('stage 6/10'), m(' · sandbox warm'),
      m(' · '), [' resumable ', 'c-success']], W, 'i2'),
    window.row([T('   '), [' ⏵ ', 'c-warn'], m('  '), p('triage'),
      m('         r-2119 · '), p('7 pending'),
      m(' · '), [' resumable ', 'c-success']], W, 'i3'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('UNCOMMITTED · operator changes outside kuzushi', W, 's2'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('apps/web/agents/refund-bot.ts'),
      m('  · 14 lines · last touched by you '), p('14:08'),
      m(' · '), [' not staged ', 'c-warn']], W, 'u1'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('package.json'),
      m('                    · '), m('1 line · '),
      [' not staged ', 'c-warn']], W, 'u2'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('NOT YET STORIED · today\'s significant moments', W, 's3'),
    window.row([T('   '), [' ▸ ', 'c-warn'], m('  '), p('F-0012 verified + patched'),
      m(' (1h 14m)'),  m('  ·  '),
      p('threat-model v3 published'),  m('  ·  '),
      p('budget hard-stop')], W, 'st1'),
    window.row([T('   '), m('   '), a('/story --audience triage'),
      m('  takes ~ 18s · '), m('drafts a memo to share before standup')], W, 'st2'),
    window.blankRow(W, 'b5'),
    window.sectionHeader('CHOOSE', W, 's4'),
    window.row([T('   '), [' Y ', 'c-success'], m('  '), p('checkpoint all + /story + quit'),
      m('   recommended · ~ 22s · everything resumable next session')], W, 'op1'),
    window.row([T('   '), [' y ', 'c-success'], m('  '), p('checkpoint all + quit'),
      m('             ~ 4s · resumable but no memo')], W, 'op2'),
    window.row([T('   '), [' p ', 'c-accent'], m('  '), p('keep running in background'),
      m('         detach the TUI · agents continue · '),
      p('kuzushi reattach'), m(' returns')], W, 'op3'),
    window.row([T('   '), [' a ', 'c-accent'], m('  '), p('abort runs + quit'),
      m('                 throws away in-flight work · audit row written')], W, 'op4'),
    window.row([T('   '), [' n ', 'c-muted'],   m('  '), p('cancel'),
      m('                            stay here')], W, 'op5'),
    window.blankRow(W, 'b6'),
    window.logLine('flow','15:59:14',[m(' '), m('default in 30s · '),
      [' Y · checkpoint all + /story + quit ', 'c-success']], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /quit · with dirty work">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'quit', cost: '$6.84' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'quit · 3 in flight · 2 unstaged · default in 30s', findings: 38,
        promptModule: 'quit',
        keybinds: [['Y','checkpoint+story+quit'],['y','checkpoint+quit'],['p','detach'],['n','cancel']],
      })}
    </window.TermFrame>
  );
}
window.QuitConfirmView = QuitConfirmView;
