// secret-scan · with hits + redaction

function SecretScanHitsView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function r(focused, id, kind, where, age, prov) {
    const sevMap = { live:'c-sev-critical', stale:'c-sev-medium', false:'c-sev-low' };
    const idCell = (id + ' '.repeat(10)).slice(0, 8);
    const kCell  = (kind + ' '.repeat(28)).slice(0, 24);
    const wCell  = (where + ' '.repeat(40)).slice(0, 36);
    const aCell  = (age + ' '.repeat(14)).slice(0, 12);
    if (focused) {
      const text = ' ' + idCell + kCell + wCell + aCell + prov;
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [idCell, 'c-accent'],
      [kCell, 'c-primary'],
      [wCell, 'c-muted'],
      [aCell, sevMap[age.includes('live') ? 'live' : age.includes('stale') ? 'stale' : 'false']],
      [prov, 'c-muted'],
    ], W, id);
  }

  const heads = window.row([
    ['    ', null],
    [('id' + ' '.repeat(8)).slice(0, 8), 'c-label'],
    [('kind' + ' '.repeat(24)).slice(0, 24), 'c-label'],
    [('where' + ' '.repeat(36)).slice(0, 36), 'c-label'],
    [('age' + ' '.repeat(12)).slice(0, 12), 'c-label'],
    ['provenance', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','15:40:01',[m(' /run secret-scan')], W, 'l1'),
    window.logLine('ok','15:40:14',[m(' done · '), p('1284 files'), m(' · '),
      p('5 hits'), m(' · '), p('2 live'), m(' · '), p('1 stale'), m(' · '), p('2 false-positive')], W, 'l2'),
    window.blankRow(W, 'b1'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'rule'),
    r(true,  'F-0061', 'aws-secret-access-key',     'apps/api/src/main.rs:14',                   'live',         'tested · sts:get-caller-identity ok'),
    r(false, 'F-0062', 'github-personal-token',     '.envrc:8',                                  'live',         'tested · /user 200'),
    r(false, 'F-0063', 'stripe-restricted-key',     'jobs/refund/legacy.py:42',                   'stale (rotated)','tested · 401 invalid_api_key'),
    r(false, 'F-0064', 'JWT (HS256)',               'docs/admin-runbook.md:128',                  'false-positive','example · @kuzushi-ignore in surrounding lines'),
    r(false, 'F-0065', 'private-key (rsa)',         'tests/fixtures/test-cert.pem',               'false-positive','test fixture · 1024-bit · noise'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('LIVE · F-0061 · aws-secret-access-key', W, 's1'),
    window.row([T('   '), m('file        '), p('apps/api/src/main.rs:14')], W, 'd1'),
    window.row([T('   '), m('snippet     '), p('let creds = "AKIA****'),
      [' [redacted in this view] ', 'c-warn'],
      p('";')], W, 'd2'),
    window.row([T('   '), m('blame       '), p('avi.k · 2026-04-21 · "wire up s3 read in dev"')], W, 'd3'),
    window.row([T('   '), m('test        '), p('sts:get-caller-identity'), m(' · '), [' 200 OK ', 'c-success'], m(' · live in account '), p('acme-prod-1418')], W, 'd4'),
    window.row([T('   '), m('rotation    '), m('owner '), p('infra-sre@acme'), m(' · sla '), p('rotate within 1h once disclosed')], W, 'd5'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('REMEDIATION', W, 's2'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('/use patch F-0061'),
      m('         draft a patch that moves to env + sets up vault binding')], W, 'm1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('/use patch F-0061 --rewrite-history'),
      m(' offer git filter-repo plan · '), [' irreversible ', 'c-danger']], W, 'm2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('/use story --finding F-0061 --audience sre'),
      m('  ticket draft for rotation')], W, 'm3'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('VIEWING POLICY', W, 's3'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  this view '),
      [' redacts ', 'c-warn'],
      m(' the secret string · only the prefix is shown · the full value is in '),
      p('.kuzushi/findings/F-0061.json'),
      m(' (mode 600, owner-only)')], W, 'p1'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), a('/show secret F-0061 --reveal'),
      m(' echoes the full value AFTER yubikey cosign · audited as '),
      p('reveal.secret'), m(' event')], W, 'p2'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '),
      a('/copy F-0061'),
      m(' streams to clipboard via pbcopy/xclip · clears in 30s · '),
      [' refused ', 'c-danger'], m(' on shared X11 sessions')], W, 'p3'),
  ];

  return (
    <window.TermFrame title="kuzushi · secret-scan · 5 hits · 2 live">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'secret-scan', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'secret-scan · 5 hits · 2 live · 1 stale', findings: 40,
        promptModule: 'secret-scan',
        keybinds: [['j/k','row'],['enter','open'],['/use patch','fix'],['--reveal','full']],
      })}
    </window.TermFrame>
  );
}
window.SecretScanHitsView = SecretScanHitsView;
