// /use verify F-0027 · sandbox spinning up

function VerifySandboxView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function step(state, label, detail) {
    const map = {
      done: [' ✓ ', 'c-success'],
      now:  [' ⏵ ', 'c-warn'],
      wait: [' · ', 'c-subtle'],
      fail: [' ✗ ', 'c-danger'],
    };
    return [
      [' ', null], map[state], [' ', null],
      [(label + ' '.repeat(38)).slice(0, 32), state === 'now' ? 'c-warn' : 'c-primary'],
      [detail, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in','15:26:01',[m(' /use verify '), a('F-0027')], W, 'l1'),
    window.logLine('run','15:26:01',[m(' verify cross-lang taint py→ts via redis-q · spawning sandbox')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('SANDBOX · sandbox-acme-r2117-01', W, 's1'),
    window.row(step('done', 'pull image',                     'kuzushi/sandbox:firejail-0.9.72'), W, 's1a'),
    window.row(step('done', 'build profile',                  'allow refund.acme · deny everything else'), W, 's1b'),
    window.row(step('done', 'mount workspace ro',             '/work · 482 files'), W, 's1c'),
    window.row(step('done', 'stage redis stub',               'docker run redis:7-alpine in jail · 6379'), W, 's1d'),
    window.row(step('done', 'stage py worker stub',           'jobs/worker/run.py via uv · 0.6s'), W, 's1e'),
    window.row(step('now',  'stage ts api stub',              'tsx apps/web/server.ts · compiling…'), W, 's1f'),
    window.row(step('wait', 'inject canary into review.body', 'KUZUSHI_CANARY_F0027=…'), W, 's1g'),
    window.row(step('wait', 'fire reproduction',              'POST /api/refund · expect canary in worker logs'), W, 's1h'),
    window.row(step('wait', 'observe',                        'tail worker.log for canary line'), W, 's1i'),
    window.row(step('wait', 'verdict',                        'reachable / not-reachable / inconclusive'), W, 's1j'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('LIVE · stage 6/10 · ts api stub', W, 's2'),
    window.row([T('   '), m('cmd     '), p('tsx apps/web/server.ts')], W, 'l3a'),
    window.row([T('   '), m('elapsed '), p('00:11s'),  m('   est '), p('~ 00:18s'),
      m('   stage timeout '), p('60s'),  m('   total budget '), p('5m')], W, 'l3b'),
    window.row([T('   '), m('output  '), p('compiling apps/web/agents/refund-bot.ts ...')], W, 'l3c'),
    window.row([T('   '), m('        '), p('compiling apps/web/agents/concierge.ts ...')], W, 'l3d'),
    window.row([T('   '), m('        '), p('compiling apps/web/server.ts ...')], W, 'l3e'),
    window.row([T('   '), m('        '), p('listen 127.0.0.1:8080 (jail-internal) — pending ready')], W, 'l3f'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('SAFETY', W, 's3'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  network egress '), p('denied'),
      m(' · only refund.acme allowed (via stub)')], W, 'sa1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  fs writes      '), p('denied to host'),
      m(' · /work mounted ro · sandbox-tmpfs writeable')], W, 'sa2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  canary scope   '), p('only F-0027'),
      m(' · refused if reproduces unrelated finding')], W, 'sa3'),
    window.row([T('   '), [' · ', 'c-subtle'], m('  /pause aborts gracefully · '),
      a('/sandbox shell'), m(' attaches a debug shell')], W, 'sa4'),
  ];

  return (
    <window.TermFrame title="kuzushi · verify · F-0027 · sandbox spinning">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'verify', cost: '$0.04' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'verify · F-0027 · sandbox stage 6/10', findings: 38,
        promptModule: 'verify',
        keybinds: [['/pause','halt'],['/sandbox shell','attach'],['l','tail logs']],
      })}
    </window.TermFrame>
  );
}
window.VerifySandboxView = VerifySandboxView;
