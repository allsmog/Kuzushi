// network down

function NetworkDownView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('err','16:06:01',[m(' '), [' NETWORK DOWN ', 'c-danger'],
      m(' · '), p('no route to api.anthropic.com'),
      m(' · '), p('no route to api.openai.com'),
      m(' · '), p('localhost models reachable')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('REACHABILITY · last 60s', W, 's1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('localhost              '),  m(' '),
      p('ollama@127.0.0.1:11434'),  m(' · 18ms')], W, 'r1'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  '), p('api.anthropic.com      '),  m(' '),
      p('timeout (5s)'),  m(' · last 6/6 attempts')], W, 'r2'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  '), p('api.openai.com         '),  m(' '),
      p('timeout (5s)'),  m(' · last 6/6 attempts')], W, 'r3'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  '), p('share.kuzushi.dev      '),  m(' '),
      p('dns refused')], W, 'r4'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('1.1.1.1                '),  m(' '),
      p('icmp ok'),  m(' · 9ms')], W, 'r5'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  '), p('cloudflare.com (https) '),  m(' '),
      p('tcp ok · tls handshake fails'),  m(' · '),
      [' MITM-ish ', 'c-warn']], W, 'r6'),
    window.row([T('   '), m('verdict '), p('partial'),
      m(' · icmp + dns to known good ips works · tls broken on outbound api hosts'),
      m(' · most likely: '), p('captive portal'), m(' · or '),
      p('corporate tls inspection without ca trust')], W, 'r7'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('AUTOMATIC RESPONSE', W, 's2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('paused all model-bound runs'),
      m(' · 3 in flight · checkpointed')], W, 'a1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('switched router to local-only'),
      m(' · '), p('ollama:llama-3.1-70b'), m(' · '),
      p('ollama:codestral'),  m(' · cost $0')], W, 'a2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('flagged actors that need cloud'),
      m(' · '), p('attacker'), m(' (carlini class) · downgraded to '),
      p('local-attacker (smaller)'), m(' if you confirm')], W, 'a3'),
    window.row([T('   '), [' · ', 'c-subtle'], m('  '), p('audit row'),
      m(' audit.log:1864 op=net:lost cause=tls-handshake')], W, 'a4'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('YOUR OPTIONS', W, 's3'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('w'),
      m(' keep waiting           '), m('   poll every 10s · auto-resume on first ok')], W, 'o1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('l'),
      m(' resume on local models '), m('   accept downgraded actor · '),
      p('local-attacker'), m(' · slower · cost $0')], W, 'o2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('p'),
      m(' edit proxy / ca trust  '), m('   '),
      a('/setg net.proxy http://corp:3128'),  m('  ·  '),
      a('/setg net.ca /etc/corp.pem')], W, 'o3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), a('d'),
      m(' run /doctor            '), m('   full reachability + tls trust report')], W, 'o4'),
    window.row([T('   '), [' 5 ', 'c-accent'], m('  '), a('n'),
      m(' stop                   '), m('   exit kuzushi · runs are checkpointed')], W, 'o5'),
    window.blankRow(W, 'b4'),
    window.row([T('   '), m('default in '), p('30s'),
      m(' · '), [' w · keep waiting ', 'c-success']], W, 'def'),
  ];

  return (
    <window.TermFrame title="kuzushi · network down · partial reachability">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$6.84' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'network · partial · 3 runs paused · default w', findings: 38,
        keybinds: [['w','wait'],['l','local'],['p','proxy'],['d','doctor'],['n','stop']],
      })}
    </window.TermFrame>
  );
}
window.NetworkDownView = NetworkDownView;
