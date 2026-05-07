// chrome-rce · no-target

function ChromeRceNoTargetView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('in','15:16:01',[m(' /use '), a('chrome-rce')], W, 'l1'),
    window.logLine('in','15:16:08',[m(' /run chrome-rce:scan')], W, 'l2'),
    window.logLine('err','15:16:08',[m(' '), [' refused ', 'c-danger'],
      m(' · no target chrome instance configured')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('PROBE · auto-discovery', W, 's1'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  '), p('CHROME_DEBUGGING_HOST'), m('  unset')], W, 'p1'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  '), p('config chrome.debug-url'), m(' unset')], W, 'p2'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  '), p('http://127.0.0.1:9222/json/version'), m('  no listener')], W, 'p3'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  '), p('puppeteer.local'), m('         no socket')], W, 'p4'),
    window.row([T('   '), [' · ', 'c-subtle'], m('  '), p('headless · /tmp/chrome-jail'),
      m('  not spawned (would create on accept)')], W, 'p5'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('TARGET MODES', W, 's2'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('--attach 127.0.0.1:9222'),
      m('         attach to your existing chrome with --remote-debugging-port=9222')], W, 'm1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('--spawn-headless'),
      m('               kuzushi spawns a sandboxed chromium · '),
      [' confirms egress per nav ', 'c-warn']], W, 'm2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('--spawn-headed --user-data-dir /tmp/cr'),
      m(' visible chrome · scriptable via cdp')], W, 'm3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), a('--against-extension <crx>'),
      m('       static-only scan · no chrome instance needed')], W, 'm4'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('SAFETY GATES (will trigger if you /run)', W, 's3'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('approval.chrome-attach'),
      m(' · operator must approve attach to a real browser')], W, 'g1'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('network egress'),
      m(' · each navigated origin needs allowlist or per-nav confirm')], W, 'g2'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('no real-creds'),
      m(' · refused if profile contains saved logins or session cookies')], W, 'g3'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','15:16:08',[m(' suggested · '),
      a('/setg chrome.mode spawn-headless'), m(' · '),
      a('/run chrome-rce:scan {"crx":"./dist.crx"}'), m(' · '),
      a('doctor'), m(' for full preflight')], W, 'l4'),
  ];

  return (
    <window.TermFrame title="kuzushi · chrome-rce · NO TARGET">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'chrome-rce', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'chrome-rce · refused · no target', findings: 38,
        promptModule: 'chrome-rce',
        keybinds: [['--attach','existing'],['--spawn','headless'],['--against','crx'],['doctor','preflight']],
      })}
    </window.TermFrame>
  );
}
window.ChromeRceNoTargetView = ChromeRceNoTargetView;
