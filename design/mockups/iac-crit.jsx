// /run iac-scan · critical state

function IacCritView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function f(focused, id, sev, name, where) {
    const sevMap = { critical:'c-sev-critical', high:'c-sev-high', medium:'c-sev-medium' };
    const idCell = (id + ' '.repeat(8)).slice(0, 6);
    const sCell  = (sev.toUpperCase() + ' '.repeat(10)).slice(0, 9);
    const nCell  = (name + ' '.repeat(64)).slice(0, 60);
    if (focused) {
      const text = ' ' + idCell + sCell + nCell + where;
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [idCell, 'c-accent'],
      [sCell, sevMap[sev]],
      [nCell, 'c-primary'],
      [where, 'c-muted'],
    ], W, id);
  }

  const lines = [
    window.logLine('in','15:42:01',[m(' /run iac-scan')], W, 'l1'),
    window.logLine('run','15:42:01',[m(' targets '), p('infra/k8s'),  m(' + '),
      p('infra/terraform'), m(' + '), p('Dockerfile'), m(' · 47 + 18 + 6 files')], W, 'l2'),
    window.logLine('ok','15:42:14',[m(' '), [' done ', 'c-success'], m(' · '),
      p('14 hits'), m(' · '), p('2 critical'), m(' · '), p('5 high'), m(' · '),
      p('7 medium')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.row([
      ['    ', null],
      [('id' + ' '.repeat(6)).slice(0, 6), 'c-label'],
      [('sev' + ' '.repeat(9)).slice(0, 9), 'c-label'],
      [('issue' + ' '.repeat(60)).slice(0, 60), 'c-label'],
      ['where', 'c-label'],
    ], W, 'h'),
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'r'),
    f(true,  'F-0034', 'critical', 'k8s deployment runs as root + privileged: true',  'infra/k8s/api.yaml:14'),
    f(false, 'F-0035', 'critical', 's3 bucket prod-customer-pii has public-read acl', 'infra/terraform/s3.tf:42'),
    f(false, 'F-0036', 'high',     'rds postgres exposed to 0.0.0.0/0 sg',            'infra/terraform/rds.tf:88'),
    f(false, 'F-0037', 'high',     'iam role attaches AdministratorAccess (lambda)',  'infra/terraform/lambda.tf:12'),
    f(false, 'F-0038', 'high',     'helm chart pulls :latest tag',                     'infra/k8s/concierge.yaml:8'),
    f(false, 'F-0039', 'high',     'docker build runs as root · USER not set',         'apps/web/Dockerfile:24'),
    f(false, 'F-0040', 'high',     'no networkpolicy in apps namespace',               'infra/k8s/apps.yaml'),
    f(false, 'F-0041', 'medium',   'eks cluster logging disabled',                     'infra/terraform/eks.tf:108'),
    f(false, 'F-0042', 'medium',   'cloudtrail not multi-region',                      'infra/terraform/audit.tf:14'),
    f(false, 'F-0043', 'medium',   'ssm doc allows ParameterStore wildcards',          'infra/terraform/ssm.tf:32'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('SELECTED · F-0034 · k8s deploy as root', W, 's1'),
    window.row([T('   '), m('manifest '), p('infra/k8s/api.yaml:14')], W, 'd1'),
    window.row([T('         '), p('   apiVersion: apps/v1')], W, 'd1a'),
    window.row([T('         '), p('   kind: Deployment')], W, 'd1b'),
    window.row([T('         '), p('   spec.template.spec.securityContext: {}')], W, 'd1c'),
    window.row([T('         '), [' + ', 'c-warn'], p('     runAsNonRoot: true')], W, 'd1d'),
    window.row([T('         '), [' + ', 'c-warn'], p('     runAsUser: 65532')], W, 'd1e'),
    window.row([T('         '), p('   spec.template.spec.containers[0].securityContext.privileged: '), [' true', 'c-danger']], W, 'd1f'),
    window.row([T('         '), [' + ', 'c-warn'], p('   ··· privileged: false')], W, 'd1g'),
    window.row([T('         '), [' + ', 'c-warn'], p('   ··· allowPrivilegeEscalation: false')], W, 'd1h'),
    window.row([T('         '), [' + ', 'c-warn'], p('   ··· capabilities: { drop: [ALL] }')], W, 'd1i'),
    window.blankRow(W, 'b3'),
    window.row([T('   '), m('blast '), p('host kernel reachable · CAP_SYS_ADMIN '),
      [' yes ', 'c-danger'], m(' · breakout class: PoC against runc 1.1.x exists')], W, 'd2'),
    window.row([T('   '), m('admission '), p('opa/gatekeeper · '), [' missing ', 'c-warn'],
      m(' · would have blocked')], W, 'd3'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('CROSS-LINK', W, 's2'),
    window.row([T('   '), [' ▸ ', 'c-warn'], p('F-0035'),
      m(' · same root cause: '), p('helm-chart-template'), m(' inherits from '),
      p('infra/k8s/_base/'),  m(' which has no securityContext defaults')], W, 'cl1'),
    window.row([T('   '), [' ▸ ', 'c-warn'], p('F-0039'),
      m(' · containers come up root-by-default · same advisory class')], W, 'cl2'),
    window.row([T('   '), m('   '), a('/use patch F-0034 --apply-class'),
      m('  fixes F-0034, F-0035, F-0039 in one staged patch (3 files)')], W, 'cl3'),
  ];

  return (
    <window.TermFrame title="kuzushi · iac-scan · 14 hits · 2 critical">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'iac-scan', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'iac-scan · 14 hits · 2 crit · 5 high', findings: 38,
        promptModule: 'iac-scan',
        keybinds: [['j/k','row'],['enter','expand'],['/use patch','draft'],['--apply-class','batch fix']],
      })}
    </window.TermFrame>
  );
}
window.IacCritView = IacCritView;
