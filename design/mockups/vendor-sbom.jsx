// /use vendor-assessment · SBOM intake

function VendorSbomView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function row(focused, vendor, sbom, kev, blast, score) {
    const vCell = (vendor + ' '.repeat(28)).slice(0, 24);
    const sCell = (sbom + ' '.repeat(18)).slice(0, 16);
    const kCell = (kev + ' '.repeat(10)).slice(0, 8);
    const bCell = (blast + ' '.repeat(38)).slice(0, 34);
    const cCell = score;
    if (focused) {
      const text = ' ' + vCell + sCell + kCell + bCell + cCell;
      return <span className="row" key={vendor}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [vCell, 'c-primary'],
      [sCell, 'c-muted'],
      [kCell, kev === '0' ? 'c-success' : 'c-warn'],
      [bCell, 'c-muted'],
      [cCell, score.includes('high') ? 'c-danger' : score.includes('med') ? 'c-warn' : 'c-success'],
    ], W, vendor);
  }

  const lines = [
    window.logLine('in','15:56:01',[m(' /use vendor-assessment '), a('--sbom intake')], W, 'l1'),
    window.logLine('run','15:56:01',[m(' source '), p('procurement/vendors/'), m(' · spdx + cyclonedx · '),
      p('14 vendors'),  m(' · '), p('41 sboms'),  m(' · '), p('cisa-kev fresh')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.row([
      ['    ', null],
      [('vendor' + ' '.repeat(24)).slice(0, 24), 'c-label'],
      [('sbom (latest)' + ' '.repeat(16)).slice(0, 16), 'c-label'],
      [('kev' + ' '.repeat(8)).slice(0, 8), 'c-label'],
      [('blast' + ' '.repeat(34)).slice(0, 34), 'c-label'],
      ['risk', 'c-label'],
    ], W, 'h'),
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'r'),
    row(true,  'orca-llm',          '2026-04-28',     '2',  'edge prompt-router · all webhooks',     'high · re-eval'),
    row(false, 'plaid (banking)',   '2026-05-01',     '0',  'cards backend · linked accounts',        'low'),
    row(false, 'segment',           '2026-05-02',     '0',  'analytics ingest only',                  'low'),
    row(false, 'sendgrid',          '2026-04-14',     '1',  'transactional email · refund-confirm',   'med'),
    row(false, 'stripe-connect',    '2026-04-30',     '0',  'connected accounts payouts',             'low'),
    row(false, 'okta-workforce',    '2026-05-02',     '1',  'sso for refund-bot operator console',     'med'),
    row(false, 'datadog-rum',       '2026-04-22',     '0',  'browser sessions · pii-scrubbed',        'low'),
    row(false, 'cloudflare-access', '2026-05-01',     '0',  'admin path · device-trust on',           'low'),
    row(false, 'redis-cloud',       '2026-04-28',     '0',  'session + queue · edge in eu-west',       'low'),
    row(false, 'launchdarkly',      '2026-04-22',     '0',  'flag eval client-side · no creds',       'low'),
    row(false, 'amplitude',         '2026-04-12',     '0',  'product analytics',                      'low'),
    row(false, 'twilio (sms)',       '2026-04-14',     '0',  'mfa fallback only',                      'low'),
    row(false, 'github (vcs)',      'native',          '0',  'source · gha · packages',                'low'),
    row(false, 'aws (root)',        'native',          '1',  'all infra · iam · rds · s3 · eks',       'med · iam-priv'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('SELECTED · orca-llm · prompt-router · 2 KEV', W, 's1'),
    window.row([T('   '), m('component '), p('orca-llm/router 2.4.1')], W, 'd1'),
    window.row([T('   '), m('kev #1    '), p('CVE-2026-2904'),  m(' · '),
      [' SSRF via tools.url ', 'c-warn'],  m(' · added '), p('2026-04-30')], W, 'd2'),
    window.row([T('   '), m('kev #2    '), p('CVE-2026-2899'),  m(' · '),
      [' arbitrary tool-arg ', 'c-warn'],  m(' · added '), p('2026-04-22')], W, 'd3'),
    window.row([T('   '), m('blast     '), p('every prompt routed through their edge'),
      m(' · sees '), p('user prompt + tool args'),  m(' · stores '), p('30d')], W, 'd4'),
    window.row([T('   '), m('mitigation'), p('upgrade to 2.4.5'),
      m(' · or pin to '), p('aws bedrock direct'),  m(' · ndiff has the patch shape')], W, 'd5'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('CROSS-LINK', W, 's2'),
    window.row([T('   '), [' ▸ ', 'c-warn'], p('F-0012 + F-0027'),
      m(' both '), p('cross orca-llm'), m(' · attacker control of '),
      p('review.body'), m(' becomes attacker control of '),
      p('orca routing'), m(' · escalation path')], W, 'cl1'),
    window.row([T('   '), m('   '), a('/use threat-model --add-vendor orca-llm:2.4.1'),
      m('  surface in v3 risks')], W, 'cl2'),
    window.row([T('   '), m('   '), a('/use ndiff CVE-2026-2904 --workspace ./ + vendor:orca-llm'),
      m('  variant hunt')], W, 'cl3'),
  ];

  return (
    <window.TermFrame title="kuzushi · vendor-assessment · 14 vendors">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'vendor-assessment', cost: '$0.04' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'vendor-assessment · 14 · 1 high · 3 med', findings: 38,
        promptModule: 'vendor-assessment',
        keybinds: [['j/k','vendor'],['enter','expand'],['/use ndiff','hunt'],['/threat-model','link']],
      })}
    </window.TermFrame>
  );
}
window.VendorSbomView = VendorSbomView;
