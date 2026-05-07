// Recon view — `/use recon` then progressive nmap → subdomain → http-fingerprint.

function ReconView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  // Format a host/port hit as a single log line
  const hit = (host, port, svc, banner) => [
    [' ', null],
    [host, 'c-primary'],
    [':', 'c-subtle'],
    [String(port), 'c-accent'],
    ['  ', null],
    [(svc + ' '.repeat(14)).slice(0, 14), 'c-muted'],
    [banner, 'c-primary'],
  ];

  const lines = [
    window.logLine('in', '14:11:02', [m(' /use '), a('recon')], W, 'l1'),
    window.logLine('in', '14:11:14', [m(' /run nmap '), a('--target acme-checkout.com --ports top-1000')], W, 'l2'),
    window.logLine('run', '14:11:14', [m(' recon:nmap · syn-scan · estimating 22s')], W, 'l3'),
    window.sectionHeader('OPEN PORTS', W, 'sec1'),
    window.logLine('find', '14:11:31', hit('acme-checkout.com', 22,  'ssh',     'OpenSSH 9.2p1 Debian'), W, 'h1'),
    window.logLine('find', '14:11:31', hit('acme-checkout.com', 80,  'http',    '301 → https'), W, 'h2'),
    window.logLine('find', '14:11:31', hit('acme-checkout.com', 443, 'https',   'nginx/1.24 · TLS1.3'), W, 'h3'),
    window.logLine('find', '14:11:32', hit('acme-checkout.com', 5432,'postgres','exposed · auth required'), W, 'h4'),
    window.logLine('find', '14:11:32', hit('acme-checkout.com', 9090,'http',    'prometheus 2.49 · NO AUTH'), W, 'h5'),
    window.blankRow(W, 'b1'),

    window.logLine('in', '14:11:48', [m(' /run subdomain '), a('--root acme-checkout.com')], W, 'l4'),
    window.logLine('run', '14:11:48', [m(' recon:subdomain · ct-logs + dns-bruteforce')], W, 'l5'),
    window.sectionHeader('SUBDOMAINS · 7 of 23', W, 'sec2'),
    window.row([T('   '), p('api.acme-checkout.com           '), m('A 34.x.x.x · cloudflare')], W, 's1'),
    window.row([T('   '), p('admin.acme-checkout.com         '), m('A 34.x.x.x · '), ['BASIC AUTH', 'c-warn']], W, 's2'),
    window.row([T('   '), p('staging.acme-checkout.com       '), m('A 34.x.x.x · '), ['NO TLS', 'c-danger']], W, 's3'),
    window.row([T('   '), p('legacy-pay.acme-checkout.com    '), m('A 34.x.x.x · '), ['heroku-23 deprecated', 'c-warn']], W, 's4'),
    window.row([T('   '), p('docs.acme-checkout.com          '), m('CNAME readme.io')], W, 's5'),
    window.row([T('   '), p('mailgun.acme-checkout.com       '), m('CNAME mailgun.org')], W, 's6'),
    window.row([T('   '), p('jenkins-old.acme-checkout.com   '), m('A 34.x.x.x · '), ['DANGLING — takeover candidate', 'c-danger']], W, 's7'),
    window.row([T('   '), m('   … 16 more · '), a('/show subdomains all')], W, 's-more'),

    window.blankRow(W, 'b2'),
    window.logLine('in', '14:12:09', [m(' /run http-fingerprint '), a('admin.acme-checkout.com')], W, 'l6'),
    window.logLine('agent', '14:12:11', [
      [' admin subdomain is gated by ', 'c-primary'],
      ['HTTP Basic', 'c-warn'],
      [' — realm string flagged.', 'c-primary'],
    ], W, 'l7'),
    window.logLine('flow', '14:12:11', [
      [' realm ', 'c-muted'], ['"acme-internal"', 'c-accent'],
      [' matches a wordlist — send to ', 'c-muted'],
      ['/use prompt-armor', 'c-accent'], [' for creds review', 'c-muted'],
    ], W, 'l7b'),
    window.logLine('log', '14:12:11', [m(' persisted '), p('3 findings'), m(' to '), p('.kuzushi/v2/findings.sqlite3')], W, 'l8'),
  ];

  return (
    <window.TermFrame title="kuzushi · recon · nmap → subdomain → http-fingerprint">
      {window.statusStrip({ target: 'acme-checkout.com', ctx: 'fresh (10m ago)', module: 'recon', cost: '$0.04' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end-1')}
      {window.footer({
        stage: 'recon:http-fingerprint (done)', findings: 3,
        promptModule: 'recon',
        keybinds: [
          ['/show', 'subdomains all'], ['/findings', 'persisted hits'],
          ['/use', 'threat-model'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.ReconView = ReconView;
