// plan-preview · agent shows multi-step plan before executing

function PlanPreviewView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function step(focused, n, label, tool, est, gate) {
    const cells = [
      [' ' + n + ' ', 'c-accent'],
      ['  ', null],
      [(label + ' '.repeat(40)).slice(0,40), 'c-primary'],
      [(tool + ' '.repeat(20)).slice(0,20), 'c-muted'],
      [(est + ' '.repeat(8)).slice(0,8), 'c-subtle'],
      gate,
    ];
    if (focused) {
      const text = ' ' + n + '  ' + (label + ' '.repeat(40)).slice(0,40)
        + (tool + ' '.repeat(20)).slice(0,20) + (est + ' '.repeat(8)).slice(0,8);
      return <span className="row" key={n}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([T('   '), ...cells], W, 'st-'+n);
  }

  const lines = [
    window.logLine('in','17:36:01',[m(' /run agentic-sast --plan ')], W, 'l1'),
    window.logLine('agent','17:36:14',[
      m(' here is the plan · '),
      p('7 steps'), m(' · est '), a('11m 40s'), m(' · est cost '), a('$0.34'), m(' · '),
      m('two writes ('), [' confirm ', 'c-warn'], m(') · '),
      m('approve to run'),
    ], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('PLAN · agentic-sast · acme-checkout', W, 's1'),
    window.row([T('   '),
      [' #  ', 'c-subtle'], [' STEP                                      ', 'c-subtle'],
      [' TOOL                ', 'c-subtle'], [' EST    ', 'c-subtle'], [' GATE', 'c-subtle']], W, 'hd'),
    window.ruleRow(W, 'r0'),
    step(true,  '1', 'load context · 4 modules · build call graph',     'context.build',         '0m 12s', m(' auto')),
    step(false, '2', 'rank attack surface · pick top-12 sinks',          'agent.reason',          '0m 48s', m(' auto')),
    step(false, '3', 'taint trace · sink #1 (refund-bot.ts:127)',        'taint-iris.trace',      '1m 20s', m(' auto')),
    step(false, '4', 'taint trace · sinks #2-#12',                        'taint-iris.trace',      '4m 18s', m(' auto')),
    step(false, '5', 'synthesize PoC · top finding',                      'sandbox.exec',          '2m 04s', [' confirm ', 'c-warn']),
    step(false, '6', 'verify · rerun PoC against patched build',          'sandbox.exec',          '1m 48s', m(' auto')),
    step(false, '7', 'write findings to ledger',                          'findings.write',        '0m 10s', [' confirm ', 'c-warn']),
    window.blankRow(W, 'b2'),
    window.sectionHeader('GATES · interactive checkpoints', W, 's2'),
    window.row([T('   '), [' ⏸ ', 'c-warn'], m('  step '), a('5'),
      m(' will run '), p('the synthesized PoC '), m('inside '), p('the sandbox · '),
      m('agent will pause for your '), a('y/n')], W, 'g1'),
    window.row([T('   '), [' ⏸ ', 'c-warn'], m('  step '), a('7'),
      m(' will write '), p('1-3 records to '), p('.kuzushi/findings.jsonl '),
      m('· agent will pause for your '), a('y/n')], W, 'g2'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('FALLBACKS', W, 's3'),
    window.row([T('   '), m('   '), p('on step-3 timeout '), a('→'), m(' skip + log · proceed'), m('   '), p('on step-5 deny '), a('→'), m(' return finding without PoC')], W, 'f1'),
    window.row([T('   '), m('   '), p('on budget breach  '), a('→'), m(' '), [' HARD STOP ', 'c-danger'], m(' before next step')], W, 'f2'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','17:36:14',[m(' '), a('y'), m(' approve plan · '),
      a('e'), m(' edit step · '),
      a('s'), m(' skip step · '),
      a('a'), m(' relax all gates (auto) · '),
      a('n'), m(' cancel')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · plan preview · 7 steps · est 11m 40s">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'planning', module: 'agentic-sast', cost: 'est $0.34' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'plan · 7 steps · 2 confirm gates · awaiting approval',
        findings: 0,
        promptModule: 'agentic-sast',
        keybinds: [['y','approve'],['e','edit step'],['s','skip step'],['a','auto gates'],['n','cancel']],
      })}
    </window.TermFrame>
  );
}
window.PlanPreviewView = PlanPreviewView;
