// budget hard-stop

function BudgetStopView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function bar(label, used, cap, color) {
    const w = 26;
    const pct = Math.min(1, used / cap);
    const filled = Math.round(w * pct);
    return [
      [(label + ' '.repeat(20)).slice(0, 18), 'c-primary'],
      [' [', 'c-subtle'],
      ['█'.repeat(filled), color || 'c-warn'],
      ['░'.repeat(Math.max(0, w - filled)), 'c-subtle'],
      ['] ', 'c-subtle'],
      [`$${used.toFixed(2)} / $${cap.toFixed(2)} `, 'c-muted'],
      [`(${Math.round(pct * 100)}%)`, color || 'c-warn'],
    ];
  }

  const lines = [
    window.logLine('run','15:46:01',[m(' '), [' HARD STOP ', 'c-danger'],
      m(' · run budget reached · '), p('r-2118'),  m(' · agentic-sast halted at frame '), p('41 / 64')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('BUDGET', W, 's1'),
    window.row([T('   '), ...bar('this run          ', 2.50, 2.50, 'c-danger')], W, 'b1a'),
    window.row([T('   '), ...bar('today (operator)  ', 6.84, 25.00,'c-success')], W, 'b1b'),
    window.row([T('   '), ...bar('today (org)       ',  142.18, 500.00, 'c-success')], W, 'b1c'),
    window.row([T('   '), ...bar('this run · time   ', 0.78, 1.00, 'c-warn')], W, 'b1d'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('STATE PRESERVED', W, 's2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('checkpoint'),
      m('       written to '), p('.kuzushi/runs/r-2118/checkpoint.bin'),  m(' · 2.4 MB')], W, 'sp1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('frames'),
      m('             flushed · '), p('41 entries'),  m(' · audit.log:1856')], W, 'sp2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('partial findings'),
      m(' kept '), p('2 candidates'),  m(' (F-0044 medium · F-0045 medium) · pending verify')], W, 'sp3'),
    window.row([T('   '), [' · ', 'c-subtle'], m('  '), p('sandbox'),
      m('            kept warm 30s · then gc')], W, 'sp4'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('YOUR OPTIONS', W, 's3'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('y'),
      m(' raise & resume     '), m('  raise this run cap to '), p('$5'),
      m(' and resume from frame '), p('41')], W, 'op1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('Y'),
      m(' raise & resume +   '), m('  same as above + raise '),
      p('today (operator)'), m(' to '), p('$50')], W, 'op2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('s'),
      m(' switch to cheaper actor '), m('  swap '), p('attacker'),
      m(' to '), p('openai:gpt-4.1-mini'), m(' (~ 6× cheaper) and resume')], W, 'op3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), a('n'),
      m(' stop and triage    '), m('  keep partial findings · '),
      a('/use triage F-0044'), m(' · '), a('/use triage F-0045')], W, 'op4'),
    window.row([T('   '), [' 5 ', 'c-accent'], m('  '), a('e'),
      m(' edit budget plan   '), m('  open '), p('/budget'),
      m('  to set per-module / per-run / per-day caps')], W, 'op5'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('WHAT BURNED THE BUDGET', W, 's4'),
    window.row([T('   '), p('actor=attacker'),  m('  '), p('148 calls'),
      m('  '), p('1.18M tok in'),  m('  '), p('142k tok out'),  m('  '), p('$2.18'),
      m('  '), [' over plan ', 'c-warn']], W, 'w1'),
    window.row([T('   '), p('actor=critic'),    m('    '), p('22 calls'),
      m('   '), p('184k tok in'),   m('   '), p('22k tok out'),   m('   '), p('$0.21')], W, 'w2'),
    window.row([T('   '), p('actor=triager'),    m('   '), p('0 calls'),
      m('     '), p('—'),  m('             '), p('—'),  m('             '), p('$0.00'),
      m('  '), m('(scheduled but not yet started)')], W, 'w3'),
    window.row([T('   '), p('overhead'),         m('         '), p('11 calls (kb:fetch, fs:read)'),
      m(' (free tools)'),  m('   '), p('$0.11')], W, 'w4'),
  ];

  return (
    <window.TermFrame title="kuzushi · BUDGET HARD STOP · r-2118">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'agentic-sast', cost: '$2.50' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'budget · HARD STOP · 41/64 frames · checkpoint saved', findings: 38,
        promptModule: 'agentic-sast',
        keybinds: [['y','raise & resume'],['s','switch actor'],['n','triage'],['e','/budget']],
      })}
    </window.TermFrame>
  );
}
window.BudgetStopView = BudgetStopView;
