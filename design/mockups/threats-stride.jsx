// /threats stride — STRIDE-only zoom (no DFD).

function ThreatStrideView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function row(focused, cat, severity, asset, finding, mitig) {
    const sMap = { critical: 'c-sev-critical', high: 'c-sev-high', medium: 'c-sev-medium', low: 'c-sev-low' };
    const cMap = {
      Spoofing: 'c-sev-high', Tampering: 'c-sev-medium', Repudiation: 'c-sev-low',
      'Info-Disclosure': 'c-sev-critical', DoS: 'c-sev-medium', 'Elev-of-Priv': 'c-sev-high',
    };
    const cCell = (cat + ' '.repeat(18)).slice(0, 16);
    const sCell = (severity.toUpperCase() + ' '.repeat(10)).slice(0, 9);
    const aCell = (asset + ' '.repeat(22)).slice(0, 22);
    const fCell = (finding + ' '.repeat(36)).slice(0, 32);
    if (focused) {
      const text = ' ' + cCell + sCell + aCell + fCell + ' ' + (mitig + ' '.repeat(40)).slice(0, 30) + ' ';
      return <span className="row" key={cat + asset}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return [
      ['  ', null],
      [cCell, cMap[cat]],
      [sCell, sMap[severity]],
      [aCell, 'c-primary'],
      [fCell, 'c-primary'],
      [mitig, 'c-muted'],
    ];
  }
  const wrap = (v, k) => Array.isArray(v) ? window.row(v, W, k) : v;

  const heads = window.row([
    ['  ', null],
    [('category' + ' '.repeat(16)).slice(0, 16), 'c-label'],
    [('sev' + ' '.repeat(9)).slice(0, 9), 'c-label'],
    [('asset' + ' '.repeat(22)).slice(0, 22), 'c-label'],
    [('issue' + ' '.repeat(32)).slice(0, 32), 'c-label'],
    ['mitigation', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','14:23:01',[m(' /threats '), a('stride')], W, 'l1'),
    window.blankRow(W, 'b1'),
    heads,
    window.row([['  ', null], ['─'.repeat(W - 2), 'c-subtle']], W, 'r'),
    wrap(row(false,'Spoofing',       'high',     'api/jwt',          'no aud claim · token replay',     'add aud=api.acme'), 'a'),
    wrap(row(false,'Spoofing',       'high',     'mailgun.acme.com', 'dangling cname',                  'reclaim or remove'), 'b'),
    wrap(row(false,'Tampering',      'medium',   'worker-pool/amqp', 'unsigned messages',               'sign + verify @ consumer'), 'c'),
    wrap(row(false,'Repudiation',    'low',      'admin actions',    'no audit log on /admin/*',        'append-only audit'), 'd'),
    wrap(row(true ,'Info-Disclosure','critical', 's3://invoices',    'plaintext PII at db→s3',          'envelope encrypt + KMS'), 'e'),
    wrap(row(false,'Info-Disclosure','high',     'api/* logs',       'request bodies logged at info',    'redact PII fields'), 'f'),
    wrap(row(false,'Info-Disclosure','medium',   'web/static/',      'sourcemap exposed in prod',       'strip on build'), 'g'),
    wrap(row(false,'DoS',            'medium',   '/checkout/confirm','no rate-limit',                   'token bucket 10/s'), 'h'),
    wrap(row(false,'Elev-of-Priv',   'high',     'admin.acme',       'shares jwt secret with api',      'split signing keys'), 'i'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('ROLLUP', W, 's2'),
    window.row([T('  '), m(' S '), p('2'), m('  T '), p('1'), m('  R '), p('1'), m('  I '), p('3'), m('  D '), p('1'), m('  E '), p('1'),
      m('   total '), [' 9 issues ', 'c-warn'], m('  ·  highest '), [' I-critical ', 'c-danger']], W, 'r1'),
    window.blankRow(W, 'b3'),
    window.logLine('flow','14:23:01',[
      m(' '), a('/threats dfd'), m(' to see the data flow  ·  '), a('/threats stories'), m(' for narratives  ·  '), a('/threats apply'), m(' to commit'),
    ], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /threats stride">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'threat-model', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/threats stride · 9 issues', findings: 9,
        promptModule: 'threat-model',
        keybinds: [['j/k','row'],['/threats','dfd|stories|scope|summary'],['/threats apply','commit']],
      })}
    </window.TermFrame>
  );
}
window.ThreatStrideView = ThreatStrideView;
