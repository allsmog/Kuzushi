// /set, /setg, /unsetg — option mutation flow with diff preview.

function OptionsSetView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function diff(key, was, now, scope) {
    return [
      [' ', null],
      [(key + ' '.repeat(36)).slice(0, 30), 'c-muted'],
      [(was + ' '.repeat(28)).slice(0, 24), 'c-danger'],
      [' → ', 'c-subtle'],
      [(now + ' '.repeat(28)).slice(0, 24), 'c-success'],
      [scope, 'c-accent'],
    ];
  }

  const lines = [
    window.logLine('in','14:11:01',[m(' /show options '), a('sast')], W, 'l1'),
    window.logLine('run','14:11:01',[m(' '), p('sast'), m(' has '), p('14'), m(' options · '), p('3'), m(' overridden')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('OPTIONS · sast', W, 's1'),
    window.row([T('   '), m('TARGET                 '), p('~/work/acme-checkout'), m('         '), [' project ', 'c-accent']], W, 'o1'),
    window.row([T('   '), m('TASKS                  '), p('semgrep,secret-scan,agentic-sast'), [' default ', 'c-muted']], W, 'o2'),
    window.row([T('   '), m('TRIAGE                 '), p('on'), m('                              '), [' default ', 'c-muted']], W, 'o3'),
    window.row([T('   '), m('SEVERITY_FLOOR         '), p('medium'), m('                          '), [' env     ', 'c-warn']], W, 'o4'),
    window.row([T('   '), m('PARALLELISM            '), p('8'), m('                               '), [' user    ', 'c-accent']], W, 'o5'),
    window.row([T('   '), m('TIMEOUT_PER_TASK       '), p('600s'), m('                            '), [' default ', 'c-muted']], W, 'o6'),
    window.row([T('   '), m('PERSIST                '), p('on'), m('                              '), [' default ', 'c-muted']], W, 'o7'),
    window.row([T('   '), m('STORE                  '), p('.kuzushi/v2/findings.sqlite3'), m(' '), [' default ', 'c-muted']], W, 'o8'),
    window.blankRow(W, 'b2'),
    window.logLine('in','14:11:42',[m(' /set '), a('PARALLELISM'), m(' '), a('16')], W, 'l3'),
    window.logLine('in','14:11:54',[m(' /set '), a('SEVERITY_FLOOR'), m(' '), a('high')], W, 'l4'),
    window.logLine('in','14:12:03',[m(' /setg '), a('triage.auto'), m(' '), a('off')], W, 'l5'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('PENDING WRITES · 3', W, 's2'),
    window.row(diff('sast.PARALLELISM',     '8',      '16',     ' run    '), W, 'd1'),
    window.row(diff('sast.SEVERITY_FLOOR',  'medium', 'high',   ' run    '), W, 'd2'),
    window.row(diff('triage.auto',          'on',     'off',    ' global '), W, 'd3'),
    window.blankRow(W, 'b4'),
    window.row([T('   '), [' i ', 'c-accent'], m('  '), p('/set'), m(' is run-scoped · '), p('/setg'), m(' writes ~/.kuzushi/v2/options.toml · '),
      p('/unsetg'), m(' clears global')], W, 'i1'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  triage.auto = off will skip the post-scan triage actor on the next /scan')], W, 'i2'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','14:12:03',[m(' '), a('y'), m(' commit · '), a('e'), m(' edit · '), a('n'), m(' discard · '),
      a('/show options sast --after'), m(' to dry-run')], W, 'l6'),
  ];

  return (
    <window.TermFrame title="kuzushi · /set · /setg · /unsetg">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'sast', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '3 pending writes · run + global', findings: 38,
        promptModule: 'sast',
        keybinds: [['y','commit'],['e','edit'],['n','discard'],['/unsetg','clear global']],
      })}
    </window.TermFrame>
  );
}
window.OptionsSetView = OptionsSetView;
