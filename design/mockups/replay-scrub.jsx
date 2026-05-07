// /replay r-2113 · scrubber + frame view

function ReplayScrubView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function bar(at, total) {
    const w = 92;
    const pos = Math.round(w * (at / total));
    const left = '─'.repeat(pos);
    const right = '─'.repeat(w - pos - 1);
    return [
      [' ', null],
      ['frame ', 'c-muted'],
      [String(at).padStart(3), 'c-accent'],
      [' / ', 'c-muted'],
      [String(total), 'c-muted'],
      ['  [', 'c-subtle'],
      [left, 'c-success'],
      ['◆', 'c-warn'],
      [right, 'c-subtle'],
      ['] ', 'c-subtle'],
    ];
  }

  const lines = [
    window.logLine('in','14:52:01',[m(' /replay '), a('r-2113'), m(' '), a('--at 38')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row(bar(38, 64), W, 'bar'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('FRAME 38', W, 's1'),
    window.row([T('   '), m('time     '), p('+18m12s'),  m('     actor '), p('attacker'),  m('   tool  '), p('sandbox:run')], W, 'f1'),
    window.row([T('   '), m('verb     '), p('curl -X POST stub://refund.acme/review --data @poc-3.json')], W, 'f2'),
    window.row([T('   '), m('expected '), p('401 unauth'),  m('     observed '), p('200 OK · refund queued · token rejected later')], W, 'f3'),
    window.row([T('   '), m('verdict  '), [' surprising ', 'c-warn'], m('  · agent flags as ATT&CK T1059 candidate · queues a critic pass')], W, 'f4'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('SURROUNDING WINDOW · 36..40', W, 's2'),
    window.row([T('   '), [' 36 ', 'c-subtle'], m(' '), p('llm'),    m('     compose poc-3 · 4.1s · $0.012')], W, 'w1'),
    window.row([T('   '), [' 37 ', 'c-subtle'], m(' '), p('tool'),   m('    fs:read poc-3.json (drafted last turn)')], W, 'w2'),
    window.row([T('   '), [' 38 ', 'c-warn'],  m(' '), p('tool'),    m('    sandbox:run curl … · '), p('200 OK'),  m(' (this frame)')], W, 'w3'),
    window.row([T('   '), [' 39 ', 'c-subtle'], m(' '), p('critic'), m('  defender · "200 doesn\'t prove anything; check refund row id"')], W, 'w4'),
    window.row([T('   '), [' 40 ', 'c-subtle'], m(' '), p('tool'),   m('    sandbox:run psql -c "select * from refund …"')], W, 'w5'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('CONTROLS', W, 's3'),
    window.row([T('   '), [' h/l ', 'c-accent'], m('  ±1 frame   '),
      [' H/L ', 'c-accent'], m('  ±10   '),
      [' g ', 'c-accent'], m('  jump · '),
      [' [ ] ', 'c-accent'], m('  bookmark   '),
      [' / ', 'c-accent'], m('  search frames   '),
      [' f ', 'c-accent'], m('  filter by kind')], W, 'c1'),
    window.row([T('   '), [' p ', 'c-accent'], m('  play (1f/s)  '),
      [' P ', 'c-accent'], m('  play (10f/s)   '),
      [' r ', 'c-accent'], m('  reverse   '),
      [' . ', 'c-accent'], m('  step')], W, 'c2'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','14:52:01',[m(' '), a('/replay r-2113 --resume-from 38'),
      m('  to fork a new run from this point with current actor + budget')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /replay r-2113 · scrubber">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'replay', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'replay · r-2113 · frame 38/64 · paused', findings: 38,
        promptModule: 'replay',
        keybinds: [['h/l','±1'],['p','play'],['g','jump'],['/ ','search'],['--resume-from','fork']],
      })}
    </window.TermFrame>
  );
}
window.ReplayScrubView = ReplayScrubView;
