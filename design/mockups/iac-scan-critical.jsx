// iac-scan · critical findings + suggest

function IacScanCriticalView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function f(focused, id, sev, name, where, hint) {
    const sevMap = { critical:'c-sev-critical', high:'c-sev-high', medium:'c-sev-medium', low:'c-sev-low' };
    const idCell = (id + ' '.repeat(10)).slice(0, 8);
    const sCell  = (sev.toUpperCase() + ' '.repeat(10)).slice(0, 9);
    const nCell  = (name + ' '.repeat(46)).slice(0, 42);
    const wCell  = (where + ' '.repeat(36)).slice(0, 30);
    if (focused) {
      const text = ' ' + idCell + sCell + nCell + wCell + hint;
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [idCell, 'c-accent'],
      [sCell, sevMap[sev]],
      [nCell, 'c-primary'],
      [wCell, 'c-muted'],
      [hint, 'c-muted'],
    ], W, id);
  }

  const heads = window.row([
    ['    ', null],
    [('id' + ' '.repeat(8)).slice(0, 8), 'c-label'],
    [('sev' + ' '.repeat(9)).slice(0, 9), 'c-label'],
    [('finding' + ' '.repeat(42)).slice(0, 42), 'c-label'],
    [('where' + ' '.repeat(30)).slice(0, 30), 'c-label'],
    ['hint', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','15:44:01',[m(' /run iac-scan')], W, 'l1'),
    window.logLine('ok','15:44:21',[m(' done · '), p('terraform 22'), m(' · '),
      p('k8s 47'), m(' · '), p('docker 14'),
      m(' · '), p('14 hits'), m(' · '), p('2 critical · 4 high · 5 medium · 3 low')], W, 'l2'),
    window.blankRow(W, 'b1'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'r'),
    f(true,  'F-0070', 'critical', 's3 bucket public-write (acl + policy)',           'tf/storage/uploads.tf:14',         '+ versioning OFF'),
    f(false, 'F-0071', 'critical', 'k8s · privileged: true on api deployment',         'infra/k8s/api.yaml:18',            'no securityContext block'),
    f(false, 'F-0072', 'high',     'rds publicly accessible · 0.0.0.0/0',              'tf/db/main.tf:88',                 'sg sg-acme-db wide-open'),
    f(false, 'F-0073', 'high',     'k8s · runAsRoot: true (default)',                   'infra/k8s/worker.yaml:34',         'add runAsNonRoot true'),
    f(false, 'F-0074', 'high',     'docker · ADD curl | bash from a non-pinned url',    'docker/api/Dockerfile:24',         'pin sha + verify'),
    f(false, 'F-0075', 'high',     'k8s · hostPath: / mounted ro into worker',           'infra/k8s/worker.yaml:88',        'reduce to /var/log if needed'),
    f(false, 'F-0076', 'medium',   'tf · KMS rotation disabled',                        'tf/kms/main.tf:18',                'enable_key_rotation = true'),
    f(false, 'F-0077', 'medium',   'k8s · no networkPolicy · default-allow ingress',    'infra/k8s/namespace.yaml:1',       'deny-by-default ns'),
    f(false, 'F-0078', 'medium',   'docker · USER root',                                'docker/api/Dockerfile:42',          'add nonroot user uid 65532'),
    window.row([T('     '), m('… 5 more · '), a('/findings --module iac-scan'), m(' to browse all')], W, 'mor'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('F-0070 · s3 bucket public-write', W, 's1'),
    window.row([T('   '), m('rule        '), p('iac:s3-public-write')], W, 'd1'),
    window.row([T('   '), m('cwe         '), p('CWE-732 · incorrect permission assignment')], W, 'd2'),
    window.row([T('   '), m('asset       '), p('aws_s3_bucket.uploads'), m(' · ')], W, 'd3'),
    window.row([T('   '), m('current     '), p('acl = "public-read-write"'),  m(' + '),
      p('aws_s3_bucket_policy.uploads'), m(' grants Principal "*"')], W, 'd4'),
    window.row([T('   '), m('exposure    '), [' anyone can write objects ', 'c-danger'],
      m(' · '), [' anyone can read ', 'c-danger']], W, 'd5'),
    window.row([T('   '), m('owner       '), p('platform-eng@acme'),  m('   blame '),
      p('avi.k · 2026-03-08 · "tmp · enable for marketing upload, will undo"')], W, 'd6'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('SUGGESTED PATCH', W, 's2'),
    window.row([T('   '), [' ─ ', 'c-danger'], [' acl = "public-read-write"', 'c-danger']], W, 'sp1'),
    window.row([T('   '), [' + ', 'c-success'], [' acl = "private"', 'c-success']], W, 'sp2'),
    window.row([T('   '), [' + ', 'c-success'], [' versioning { enabled = true }', 'c-success']], W, 'sp3'),
    window.row([T('   '), [' + ', 'c-success'], [' server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } } }', 'c-success']], W, 'sp4'),
    window.row([T('   '), [' ─ ', 'c-danger'], [' resource "aws_s3_bucket_policy" "uploads" { …Principal="*"… }', 'c-danger']], W, 'sp5'),
    window.row([T('   '), [' + ', 'c-success'], [' resource "aws_s3_bucket_policy" "uploads" { …Principal=arn:aws:iam::acme-prod:role/upload-svc… }', 'c-success']], W, 'sp6'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('NEXT', W, 's3'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('/use patch F-0070'),
      m('               draft this fix · '), [' staged-only ', 'c-warn']], W, 'n1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('/use story --finding F-0070 --audience platform'),
      m('  open a ticket')], W, 'n2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('/use iac-scan --plan terraform'),
      m('     show terraform plan diff (will need creds · refused without /auth aws)')], W, 'n3'),
  ];

  return (
    <window.TermFrame title="kuzushi · iac-scan · 14 hits · 2 critical">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'iac-scan', cost: '$0.04' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'iac-scan · 83 files · 14 hits · 2 critical', findings: 40,
        promptModule: 'iac-scan',
        keybinds: [['j/k','row'],['enter','open'],['/use patch','fix'],['--plan','tf plan']],
      })}
    </window.TermFrame>
  );
}
window.IacScanCriticalView = IacScanCriticalView;
