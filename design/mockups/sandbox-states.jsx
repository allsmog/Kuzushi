// sandbox states · firejail / docker / running

function SandboxStatesView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function panel(title, glyph, gColor, rows) {
    const out = [];
    out.push(window.row([T('   '), ['┌─ ', 'c-subtle'], [glyph + ' ' + title + ' ', gColor],
      ['─'.repeat(W - 6 - 4 - title.length - 2), 'c-subtle'], ['┐', 'c-subtle']], W, title));
    for (const r of rows) {
      out.push(window.row([T('   '), ['│ ', 'c-subtle'], [r.padEnd(W - 8), 'c-primary'],
        [' │', 'c-subtle']], W, title+r));
    }
    out.push(window.row([T('   '), ['└', 'c-subtle'], ['─'.repeat(W - 6), 'c-subtle'],
      ['┘', 'c-subtle']], W, title+'b'));
    out.push(window.blankRow(W, title+'sp'));
    return out;
  }

  const lines = [
    window.logLine('in','15:04:01',[m(' /sandbox status')], W, 'l1'),
    window.blankRow(W, 'b1'),
    ...panel('ACTIVE · sandbox-acme-r2113-08', '⚙', 'c-success', [
      ' kind        firejail',
      ' profile     ~/.kuzushi/v2/sandbox/firejail.profile',
      ' net         allowlist · refund.acme, *.acme-checkout-stg.com',
      ' fs          read-only host · rw on /tmp/sb-r2113-08',
      ' caps        --caps.drop=all  --seccomp  --noroot',
      ' uptime      00:11:48',
      ' runs hosting r-2113',
    ]),
    ...panel('AVAILABLE · firejail', '✓', 'c-success', [
      ' version  0.9.72  ·  /usr/bin/firejail',
      ' policy   allow · default sandbox for sandbox:run',
    ]),
    ...panel('NOT INSTALLED · docker', '·', 'c-subtle', [
      ' optional · alt sandbox',
      ' install: brew install docker  ·  apt install docker.io',
      ' set with: /setg sandbox=docker',
    ]),
    ...panel('STALE · sandbox-acme-r2107-04 · paused 3h', '!', 'c-warn', [
      ' kind        firejail',
      ' last seen   12:01:22 (paused-resume sequence)',
      ' artifacts   /tmp/sb-r2107-04 · 18 MB',
      ' retention   gc on /sandbox prune  (or 24h ttl)',
    ]),
    ...panel('REFUSED · /sandbox new --kind=none', '✗', 'c-danger', [
      ' --kind=none asks to run sandbox:run on the host directly.',
      ' policy refuses · this gate is unconditional.',
      ' alternatives: --kind=firejail (default) · --kind=docker (if installed)',
    ]),
    window.row([T('   '), [' i ', 'c-accent'], m('  '), a('/sandbox prune'),
      m(' to gc stale · '), a('/sandbox shell sandbox-acme-r2113-08'),
      m(' to attach for debugging')], W, 'in1'),
  ];

  return (
    <window.TermFrame title="kuzushi · /sandbox · status">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'sandbox', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'sandbox · 1 active · 1 stale · firejail ok', findings: 38,
        promptModule: 'sandbox',
        keybinds: [['/sandbox new','spawn'],['/sandbox prune','gc'],['/sandbox shell','attach']],
      })}
    </window.TermFrame>
  );
}
window.SandboxStatesView = SandboxStatesView;
