// State: paused mid-scan, with /resume.

function PauseResumeView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function bar(label, done, total, status, color = 'c-success') {
    const w = 24;
    const pct = total === 0 ? 0 : done / total;
    const filled = Math.round(w * pct);
    const empty = w - filled;
    return [
      [(label + ' '.repeat(20)).slice(0, 20), 'c-primary'],
      [' [', 'c-subtle'],
      ['█'.repeat(filled), color],
      ['░'.repeat(empty), 'c-subtle'],
      ['] ', 'c-subtle'],
      [(`${done}/${total}`).padStart(7), 'c-muted'],
      ['  ', null],
      [status, color],
    ];
  }

  const lines = [
    window.logLine('in','14:34:41',[m(' /pause')], W, 'l1'),
    window.logLine('flow','14:34:41',[m(' draining workers · waiting on '), p('agentic-sast'), m(' frame '), p('38/64')], W, 'l2'),
    window.logLine('ok','14:34:43',[m(' '), [' paused ', 'c-warn'], m(' run '), p('r-2113'),
      m(' · state written to '), p('.kuzushi/runs/r-2113/checkpoint.bin'), m(' · 2.4 MB')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('semgrep             ', 612, 612, 'done',                   'c-success')], W, 'p1'),
    window.row([T('   '), ...bar('secret-scan         ', 1284, 1284, 'done',                 'c-success')], W, 'p2'),
    window.row([T('   '), ...bar('agentic-sast        ', 87, 120, 'paused · resumable',     'c-warn')], W, 'p3'),
    window.row([T('   '), ...bar('triage (post-scan)  ', 11, 18, 'paused · waiting',         'c-warn')], W, 'p4'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('CHECKPOINT · r-2113', W, 's1'),
    window.row([T('   '), m('frame       '), p('38 / 64'), m('  ·  '), m('actor '), p('attacker'),
      m('  ·  '), m('next tool '), p('sandbox:run')], W, 'd1'),
    window.row([T('   '), m('budget so far'), p(' $0.31'), m('  /  budget cap '), p('$2.50')], W, 'd2'),
    window.row([T('   '), m('artifacts   '), p('.kuzushi/runs/r-2113/'), m('  · '), p('22 files'),
      m(' · '), p('892 KB'), m('  ·  ttl '), p('48h')], W, 'd3'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('RESUME OPTIONS', W, 's2'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('/resume r-2113'),
      m('               continue from frame 38 with same actor + budget')], W, 'r1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('/resume r-2113 --budget 5.00'),
      m('   raise budget then continue')], W, 'r2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('/replay r-2113 --at 38'),
      m('       step through what we have so far')], W, 'r3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), a('/abort r-2113'),
      m('               discard checkpoint, keep partial findings')], W, 'r4'),
    window.blankRow(W, 'b4'),
    window.logLine('agent','14:34:43',[
      m(' '), p('33 raw hits'), m(' so far · '), p('11'), m(' triaged · '),
      [' verify F-0001 / F-0002 ', 'c-warn'],
      m(' is safe to do without resuming the umbrella'),
    ], W, 'l4'),
  ];

  return (
    <window.TermFrame title="kuzushi · /pause r-2113">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'sast', cost: '$0.41' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'paused · r-2113 · frame 38/64', findings: 11,
        promptModule: 'sast',
        keybinds: [['/resume','continue'],['/abort','discard'],['/replay','step'],['/use verify','side-quest']],
      })}
    </window.TermFrame>
  );
}
window.PauseResumeView = PauseResumeView;
