// schedule · /schedule · cron-like recurring runs

function ScheduleView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function jobRow(focused, id, name, when, what, last, next, state, stateCls) {
    if (focused) {
      const text = ' ' + id + '  ' + (name + ' '.repeat(20)).slice(0,20)
        + '  ' + (when + ' '.repeat(22)).slice(0,22)
        + (what + ' '.repeat(28)).slice(0,28)
        + (last + ' '.repeat(11)).slice(0,11)
        + (next + ' '.repeat(11)).slice(0,11) + state;
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([T('   '),
      [' ' + id + ' ', 'c-accent'],
      ['  ', null],
      [(name + ' '.repeat(20)).slice(0,20), 'c-primary'],
      ['  ', null],
      [(when + ' '.repeat(22)).slice(0,22), 'c-muted'],
      [(what + ' '.repeat(28)).slice(0,28), 'c-subtle'],
      [(last + ' '.repeat(11)).slice(0,11), 'c-muted'],
      [(next + ' '.repeat(11)).slice(0,11), 'c-muted'],
      [' ' + state + ' ', stateCls],
    ], W, id);
  }

  const lines = [
    window.logLine('in','17:14:01',[m(' /schedule ')], W, 'l1'),
    window.row([T('  '), m('6 jobs '),
      m(' · agent runs '), p('on the cadence below'), m(' · '),
      m('idempotent · de-dups against '), p('/runs'), m(' · '),
      m('next dispatch '), a('17:30 UTC')], W, 'h0'),
    window.blankRow(W, 'b1'),
    window.row([T('   '),
      [' JOB-ID  ', 'c-subtle'], [' NAME                 ', 'c-subtle'],
      [' WHEN                  ', 'c-subtle'],
      [' MODULE · TARGET            ', 'c-subtle'],
      [' LAST     ', 'c-subtle'], [' NEXT     ', 'c-subtle'], [' STATE', 'c-subtle']], W, 'hd'),
    window.ruleRow(W, 'r0'),
    jobRow(true,  'j-001', 'nightly sast',           'every day · 02:00 UTC',  'sast · acme-checkout',     '14h ago',   'in 8h 46m', 'ENABLED',  'c-success'),
    jobRow(false, 'j-002', 'weekly variant hunt',    'mon · 03:00 UTC',        'variant · acme-checkout',  '4d ago',    'in 3d 09h', 'ENABLED',  'c-success'),
    jobRow(false, 'j-003', 'hourly secret scan',     'every 1h',               'secret-scan · *',          '12m ago',   'in 48m',    'ENABLED',  'c-success'),
    jobRow(false, 'j-004', 'pre-deploy iac',         'on tag v*',              'iac-scan · infra/*',       'never',     'on tag',    'TRIGGER',  'c-accent'),
    jobRow(false, 'j-005', 'cve sweep · libxml2',    'on cve feed match',      'ndiff · vendored libs',    '2d ago',    'on feed',   'TRIGGER',  'c-accent'),
    jobRow(false, 'j-006', 'red-team weekly',        'fri · 18:00 UTC',        'agentic-sast · acme-pay',  '6d ago',    'paused',    'PAUSED',   'c-warn'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('UPCOMING · next 24h dispatch queue', W, 's1'),
    window.row([T('   '), [' 17:30 ', 'c-accent'], m(' · '), p('j-003 hourly secret scan'),  m('     · est '), a('48s'),  m('   · '), p('budget '), a('$0.04')], W, 'u1'),
    window.row([T('   '), [' 18:30 ', 'c-accent'], m(' · '), p('j-003 hourly secret scan'),  m('     · est '), a('48s'),  m('   · '), p('budget '), a('$0.04')], W, 'u2'),
    window.row([T('   '), [' 02:00 ', 'c-accent'], m(' · '), p('j-001 nightly sast'),         m('             · est '), a('4m 12s'),  m(' · '), p('budget '), a('$0.42')], W, 'u3'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('CREATE · /schedule add', W, 's2'),
    window.row([T('   '), m('   '), a('/schedule add nightly-sast --cron "0 2 * * *" -- kuzushi scan <target>')], W, 'c1'),
    window.row([T('   '), m('   '), a('/schedule add cve-libxml2 --on cve.feed.match=libxml2 -- /run ndiff --cve $CVE')], W, 'c2'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','17:14:14',[m(' '), a('j/k'), m(' job · '),
      a('enter'), m(' edit · '),
      a('p'), m(' pause · '),
      a('r'), m(' run-now · '),
      a('a'), m(' add · '),
      a('Esc'), m(' close')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /schedule · 6 jobs">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'schedule', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'schedule · 6 jobs · 5 enabled · 1 paused',
        findings: 0,
        promptModule: 'schedule',
        keybinds: [['j/k','job'],['enter','edit'],['p','pause'],['r','run-now'],['a','add']],
      })}
    </window.TermFrame>
  );
}
window.ScheduleView = ScheduleView;
