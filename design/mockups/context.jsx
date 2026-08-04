// Context view — operator just ran `/use context` then `/run build`.
// Console grows top-to-bottom; the snapshot summary is rendered as log lines.

function ContextView() {
  const W = window.W120;
  const T = (t) => [t, null];
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const s = (t) => [t, 'c-success'];

  const lines = [
    window.logLine('in', '14:02:11', [
      [' /use ', 'c-muted'], ['context', 'c-accent'],
    ], W, 'l1'),
    window.logLine('ok', '14:02:11', [
      [' focused module ', 'c-muted'], ['context', 'c-accent'],
      [' · primary tool ', 'c-muted'], ['context:build', 'c-primary'],
    ], W, 'l2'),
    window.logLine('in', '14:02:18', [
      [' /run ', 'c-muted'], ['build', 'c-accent'],
    ], W, 'l3'),
    window.logLine('run', '14:02:18', [
      [' context:build ', 'c-primary'],
      ['indexing ', 'c-muted'], ['~/work/acme-checkout', 'c-primary'],
      [' …', 'c-muted'],
    ], W, 'l4'),
    window.logLine('flow', '14:02:19', [m(' walking working tree (gitignore + .kuzushiignore honored)')], W, 'l5'),
    window.logLine('flow', '14:02:21', [m(' classifying languages · routing parsers')], W, 'l6'),
    window.logLine('flow', '14:02:24', [m(' extracting routes, env reads, sql sites, http calls')], W, 'l7'),

    window.sectionHeader('SNAPSHOT', W, 'sec-snap'),
    window.row([T('   '), m('files       '), p('1,284'), m('  total · '), p('612'), m(' indexed · '), p('38'), m(' skipped (binary, vendored)')], W, 'snap1'),
    window.row([T('   '), m('languages   '), p('typescript 58%'), m(' · '), p('rust 21%'), m(' · '), p('python 11%'), m(' · '), p('sql 4%'), m(' · '), p('other 6%')], W, 'snap2'),
    window.row([T('   '), m('entrypoints '), p('apps/web/server.ts'), m(' · '), p('apps/api/main.rs'), m(' · '), p('jobs/worker.py')], W, 'snap3'),
    window.row([T('   '), m('routes      '), p('41 http'), m(' · '), p('7 grpc'), m(' · '), p('12 cron')], W, 'snap4'),
    window.row([T('   '), m('secrets†    '), [' 0 plaintext, 4 env-templated', 'c-success']], W, 'snap5'),
    window.row([T('   '), m('sinks       '), p('sql:23'), m(' · '), p('shell:6'), m(' · '), p('http:51'), m(' · '), p('fs:18')], W, 'snap6'),
    window.row([T('   '), m('sources     '), p('http body:41'), m(' · '), p('cookies:9'), m(' · '), p('headers:12'), m(' · '), p('cli args:5')], W, 'snap7'),

    window.blankRow(W, 'b-snap'),
    window.logLine('ok', '14:02:31', [
      [' wrote ', 'c-muted'], ['.kuzushi/context-snapshot.json', 'c-primary'],
      [' (', 'c-muted'], ['184 KB', 'c-primary'], [')', 'c-muted'],
    ], W, 'l8'),
    window.logLine('agent', '14:02:31', [
      [' fresh context — sast and threat-model are now both safe to run', 'c-primary'],
    ], W, 'l9'),
    window.logLine('log', '14:02:31', [
      m(' next: '), a('/scan'), m('  ·  '), a('/use threat-model'), m('  ·  '), a('/show snapshot'),
    ], W, 'l10'),
  ];

  return (
    <window.TermFrame title="kuzushi · context · /use context → /run build">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'building (8s)', module: 'context' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end-1')}
      {window.blankRow(W, 'b-end-2')}
      {window.footer({
        stage: 'context:build (done)', findings: 0,
        promptModule: 'context',
        keybinds: [
          ['/show', 'snapshot'], ['/scan', 'Scan planner'],
          ['/back', 'catalog'], ['?', 'help'],
        ],
      })}
    </window.TermFrame>
  );
}

window.ContextView = ContextView;
