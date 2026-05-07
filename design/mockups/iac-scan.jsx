// IaC-scan view — terraform / k8s / dockerfile audit. Walks the IaC layer
// looking for misconfigurations, drift, and exposure.

function IacScanView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  function bar(label, done, total, status, color = 'c-success') {
    const width = 24;
    const pct = total === 0 ? 0 : done / total;
    const filled = Math.round(width * pct);
    const empty = width - filled;
    return [
      [(label + ' '.repeat(20)).slice(0, 20), 'c-primary'],
      [' [', 'c-subtle'],
      ['█'.repeat(filled), color],
      ['░'.repeat(empty), 'c-subtle'],
      ['] ', 'c-subtle'],
      [(`${done}/${total}`).padStart(7), 'c-muted'],
      ['  ', null],
      [status, color],
    ];
  }

  function issue(rule, sev, name, where) {
    const sevMap = { critical: 'c-sev-critical', high: 'c-sev-high', medium: 'c-sev-medium', low: 'c-sev-low' };
    return [
      [' ', null],
      [(rule + ' '.repeat(28)).slice(0, 26), 'c-accent'],
      [(sev.toUpperCase() + ' '.repeat(10)).slice(0, 9), sevMap[sev]],
      [(name + ' '.repeat(60)).slice(0, 46), 'c-primary'],
      [where, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in',  '15:38:08', [m(' /use '), a('iac-scan')], W, 'l1'),
    window.logLine('in',  '15:38:14', [m(' /run '), a('scan --include terraform,k8s,docker')], W, 'l2'),
    window.logLine('run', '15:38:14', [m(' iac-scan · '), p('212'), m(' files · 3 backends')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('terraform           ', 84, 84, 'done · 11 hits',  'c-warn')], W, 'p1'),
    window.row([T('   '), ...bar('k8s manifests       ', 96, 96, 'done · 6 hits',   'c-warn')], W, 'p2'),
    window.row([T('   '), ...bar('dockerfiles         ', 14, 14, 'done · 2 hits',   'c-warn')], W, 'p3'),
    window.row([T('   '), ...bar('helm + kustomize    ', 18, 18, 'done · 1 hit',    'c-warn')], W, 'p4'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('FINDINGS · 20 (top 10)', W, 'sec-f'),
    window.row(issue('aws.iam.wildcard-policy',   'critical', 'IAM role allows *:* on prod-data',   'infra/tf/iam/data.tf:34'), W, 'i1'),
    window.row(issue('aws.s3.public-acl',          'high',     'invoices bucket has public-read acl', 'infra/tf/s3.tf:72'), W, 'i2'),
    window.row(issue('aws.rds.no-encryption',      'high',     'rds postgres without storage_encrypted','infra/tf/rds.tf:18'), W, 'i3'),
    window.row(issue('aws.sg.open-22',             'high',     'security group ingress 0.0.0.0/0 :22','infra/tf/sg-bastion.tf:8'), W, 'i4'),
    window.row(issue('k8s.deployment.privileged',  'high',     'job runs with privileged: true',     'k8s/jobs/migrate.yaml:24'), W, 'i5'),
    window.row(issue('k8s.serviceaccount.cluster-admin','critical','sa bound to cluster-admin','k8s/rbac/ops.yaml:14'), W, 'i6'),
    window.row(issue('k8s.network.allow-all',      'medium',   'no NetworkPolicy in ns: payments',   'k8s/ns/payments.yaml'), W, 'i7'),
    window.row(issue('docker.user.root',           'medium',   'final stage runs as root',           'apps/web/Dockerfile:42'), W, 'i8'),
    window.row(issue('docker.add.untrusted',       'medium',   'ADD over http:// — use COPY',         'jobs/scrape/Dockerfile:14'), W, 'i9'),
    window.row(issue('helm.values.secret-plain',   'medium',   'plaintext db password in values.yaml','charts/api/values.prod.yaml:38'), W, 'i10'),
    window.row([T('   '), m('   … 10 more · '), a('/show iac all --severity high+')], W, 'i-more'),
    window.blankRow(W, 'b3'),

    window.sectionHeader('STATE', W, 'sec-st'),
    window.row([T('   '), m('plan diff vs state '), p('infra/tf/plan-2026-05-06.txt'), m('  ·  '), w('drift'), m(' on '), p('iam-role-checkout-api'), m(' (perms widened out-of-band)')], W, 'st1'),
    window.row([T('   '), m('untracked          '), p('1 manual change'), m(' to '), p('s3 bucket policy'), m(' · '), w('reconcile')], W, 'st2'),
    window.blankRow(W, 'b4'),

    window.logLine('agent', '15:38:48', [m(' the two CRITICALs ('), a('iam.wildcard'), m(', '), a('cluster-admin'), m(') sit on the same blast radius — fix together.')], W, 'l-end'),
    window.logLine('log', '15:38:48', [m(' wrote '), p('.kuzushi/runs/.../iac-scan.json'), m(' · '), p('persisted 20 findings')], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · iac-scan · terraform + k8s + docker">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'iac-scan', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'iac-scan (done) · 2 critical · 18 others', findings: 20,
        promptModule: 'iac-scan',
        keybinds: [
          ['/show', 'iac all | drift'], ['/use', 'patch'],
          ['/iac-scan', 'export'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.IacScanView = IacScanView;
