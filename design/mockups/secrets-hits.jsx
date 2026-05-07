// /run secret-scan · 3 hits with redactions

function SecretsHitsView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function hit(focused, id, kind, where, secret, age) {
    const idCell  = (id + ' '.repeat(8)).slice(0, 6);
    const kCell   = (kind + ' '.repeat(20)).slice(0, 18);
    const wCell   = (where + ' '.repeat(40)).slice(0, 36);
    const sCell   = (secret + ' '.repeat(28)).slice(0, 24);
    const aCell   = age;
    if (focused) {
      const text = ' ' + idCell + kCell + wCell + sCell + aCell;
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [idCell, 'c-accent'],
      [kCell, 'c-warn'],
      [wCell, 'c-primary'],
      [sCell, 'c-danger'],
      [aCell, 'c-muted'],
    ], W, id);
  }

  const lines = [
    window.logLine('in','15:38:01',[m(' /run secret-scan '), a('{"workspace":"."}')], W, 'l1'),
    window.logLine('run','15:38:01',[m(' detectors '), p('142'),  m(' · paths '), p('1284'),
      m(' · scanned '), p('142,180 SLOC')], W, 'l2'),
    window.logLine('ok', '15:38:14',[m(' '), [' done ', 'c-success'], m(' · '),
      p('3 hits'), m(' · '), p('1 verified'),  m(' · '), p('2 likely-historical')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.row([
      ['    ', null],
      [('id' + ' '.repeat(6)).slice(0, 6), 'c-label'],
      [('kind' + ' '.repeat(18)).slice(0, 18), 'c-label'],
      [('where' + ' '.repeat(36)).slice(0, 36), 'c-label'],
      [('preview (redacted)' + ' '.repeat(24)).slice(0, 24), 'c-label'],
      ['age', 'c-label'],
    ], W, 'h'),
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'r'),
    hit(true,  'S-01', 'aws-access-key',     '.env.example:14',                              'AKIA****************',     'staged'),
    hit(false, 'S-02', 'github-fine-grained', 'apps/api/scripts/seed.rs:21 (string literal)', 'github_pat_11A****…',      '2 days'),
    hit(false, 'S-03', 'jwt-private (rs256)', 'apps/api/auth/keys/dev.pem (committed)',        '-----BEGIN RSA PRI…',      '142 days'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('SELECTED · S-01 · aws-access-key', W, 's1'),
    window.row([T('   '), m('match  '), p('AKIAIOSFODNN7EXAMPLE'),  m(' (redacted in ledger as '), p('AKIA****************'), m(')')], W, 'd1'),
    window.row([T('   '), m('valid  '), [' active ', 'c-danger'],  m(' · sts:get-caller-identity returned arn:aws:iam::1234…:user/dev-jen')], W, 'd2'),
    window.row([T('   '), m('exposed'), p(' git history 412 commits · last touch by avi.k'),
      m(' · also reachable via '), p('PR412'), m(' (open)')], W, 'd3'),
    window.row([T('   '), m('blast  '), p('s3:ListBucket on 14 buckets'),
      m('   '), p('rds:describe* on prod-west2'),
      m('   '), p('NO sts:assume-role')], W, 'd4'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('REDACTION · how kuzushi handles this hit downstream', W, 's2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('audit.log'),
      m('       writes '), p('AKIA****************'), m(' (length-preserving star-mask)')], W, 're1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('agent prompts'),
      m('   are scrubbed by '), p('redactPII'), m(' middleware before any model call')], W, 're2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('exports'),
      m('         drop the file entirely if redaction would change semantics')], W, 're3'),
    window.row([T('   '), [' · ', 'c-subtle'], m('  raw secret never persisted on disk by kuzushi')], W, 're4'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('REMEDIATE', W, 's3'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('/use patch S-01'),
      m('       proposes BFG-style history rewrite + .env.example placeholder')], W, 'rm1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('aws iam delete-access-key'),
      m(' rotate now (operator runs · we don\'t auto-touch your aws account)')], W, 'rm2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('/use threat-model --note S-01 active'),
      m('  reflect cred-leak in v3 risks')], W, 'rm3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), a('/findings link S-01 r-2117'),
      m('   tie to the open verify run')], W, 'rm4'),
  ];

  return (
    <window.TermFrame title="kuzushi · secret-scan · 3 hits · 1 active">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'secret-scan', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'secret-scan · 3 hits · 1 active · 2 historical', findings: 38,
        promptModule: 'secret-scan',
        keybinds: [['j/k','row'],['enter','expand'],['/use patch','rewrite'],['?','context']],
      })}
    </window.TermFrame>
  );
}
window.SecretsHitsView = SecretsHitsView;
