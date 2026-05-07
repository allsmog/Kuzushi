// verify · sandbox spinning up · pre-PoC

function VerifySandboxSpinningView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function step(state, label, detail) {
    const sMap = { ok:[' ✓ ','c-success'], now:[' ⏵ ','c-warn'], wait:[' · ','c-subtle'], fail:[' ✗ ','c-danger'] };
    return [
      [' ', null], sMap[state],
      [(label + ' '.repeat(46)).slice(0, 42), state==='now' ? 'c-warn' : 'c-primary'],
      [detail, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in','15:26:01',[m(' /use verify '), a('F-0012')], W, 'l1'),
    window.logLine('run','15:26:01',[m(' actor '), p('verifier · openai:gpt-4.1'),
      m(' · sandbox '), p('firejail · profile prompt-injection'),
      m(' · budget '), p('$0.50')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('PREFLIGHT', W, 's1'),
    window.row(step('ok',  'finding loaded',                            'F-0012 · refund-bot.ts:127 · 14 KB · cited a-04 + a-08'), W, 'pf1'),
    window.row(step('ok',  'snapshot taken',                            '.kuzushi/snapshots/r-2117/refund-bot.ts.bak'), W, 'pf2'),
    window.row(step('ok',  'allowlist seeded',                          'refund.acme · stub://refund.acme/* · webhook-stub.acme'), W, 'pf3'),
    window.row(step('ok',  'kb fetched',                                'a-04 (4.1 KB) · a-08 (3.2 KB) · attck T1059 (1.0 KB)'), W, 'pf4'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('SANDBOX · spinning up', W, 's2'),
    window.row(step('ok',  'create profile firejail.profile.refundbot', '/tmp/sb-r2117-01/firejail.profile (rw, network ns, seccomp)'), W, 'sp1'),
    window.row(step('ok',  'tmpfs scratch dir',                          '/tmp/sb-r2117-01 · 64 MB cap · noexec'), W, 'sp2'),
    window.row(step('ok',  'image overlay',                              'host fs read-only via /usr/lib/firejail/whitelist'), W, 'sp3'),
    window.row(step('now', 'spawn process',                              'firejail --profile=… node /tmp/sb-r2117-01/refund-bot.poc.js · 1.8s'), W, 'sp4'),
    window.row(step('wait','health probe',                                'GET stub://refund.acme/healthz · expect 200'), W, 'sp5'),
    window.row(step('wait','replay decoy traffic',                       'fixture: 12 review.body benign · seed sandbox state'), W, 'sp6'),
    window.row(step('wait','run PoC',                                    'inject candidate-3 · expect refund queued for $0'), W, 'sp7'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('SANDBOX METADATA', W, 's3'),
    window.row([T('   '), m('id          '), p('sandbox-acme-r2117-01')], W, 'm1'),
    window.row([T('   '), m('caps drop   '), p('all'),  m('   seccomp '), p('strict'), m('   noroot '), p('true')], W, 'm2'),
    window.row([T('   '), m('net         '), p('allowlist · refund.acme + 127.0.0.1:* (mock listener)')], W, 'm3'),
    window.row([T('   '), m('fs          '), p('host /usr/lib · /etc/ssl ro · /tmp/sb-r2117-01 rw')], W, 'm4'),
    window.row([T('   '), m('budget cap  '), p('30s wall'),  m('   $ '), p('0.50'),  m('   tokens '), p('40k')], W, 'm5'),
    window.row([T('   '), m('on-success  '), p('write proof to .kuzushi/findings/F-0012/proof.json')], W, 'm6'),
    window.row([T('   '), m('on-failure  '), p('keep sandbox · auto-attach with /sandbox shell')], W, 'm7'),
    window.blankRow(W, 'b4'),
    window.row([T('   '), [' i ', 'c-accent'], m('  '), p('sandbox is the gate'), m(' · we never replay PoC against the real ws')], W, 'in1'),
    window.row([T('   '), [' i ', 'c-accent'], m('  '), p('paused on health-probe failure'),
      m(' · '), a('/sandbox shell sandbox-acme-r2117-01'), m(' to investigate')], W, 'in2'),
  ];

  return (
    <window.TermFrame title="kuzushi · verify · F-0012 · sandbox spinning">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'verify', cost: '$0.04' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'verify · F-0012 · sandbox spinning · 4/7', findings: 38,
        promptModule: 'verify',
        keybinds: [['/sandbox shell','attach'],['/pause','halt'],['?','agent']],
      })}
    </window.TermFrame>
  );
}
window.VerifySandboxSpinningView = VerifySandboxSpinningView;
