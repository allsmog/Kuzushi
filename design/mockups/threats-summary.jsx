// /threats summary — exec read.

function ThreatSummaryView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('in','14:27:00',[m(' /threats '), a('summary')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('product '), p('acme-checkout v1.2.1'), m('  ·  '), m('reviewer '), p('avi.k'),
      m('  ·  '), m('model '), p('STRIDE/PASTA hybrid v4'), m('  ·  '), m('updated '), p('14:21')], W, 'h1'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('TLDR', W, 's1'),
    window.row([T('  '), p('  acme-checkout has '), [' two ship-blocker risks ', 'c-danger'],
      p(' and '), [' five fixable mediums ', 'c-warn'],
      p('. Both blockers')], W, 't1'),
    window.row([T('  '), p('  cluster around '), p('apps/web/agents/'), p(' and '), p('apps/api/orders.rs'),
      p('. Net of patches in v1.2.0 we are')], W, 't2'),
    window.row([T('  '), p('  '), [' net-negative on agentic risk ', 'c-warn'],
      p(' (refund-bot added since last review).')], W, 't3'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('TOP RISKS', W, 's2'),
    window.row([T('  '), [' 1 ', 'c-sev-critical'], m('  '), p('Prompt-injection in refund-bot promotes attacker refunds'),
      m('  ·  '), m('owner '), p('@web-platform'), m('  ·  '), m('SLA '), p('3d')], W, 'r1'),
    window.row([T('  '), [' 2 ', 'c-sev-critical'], m('  '), p('SQL injection via order_id concatenation (orders.rs:142)'),
      m('  ·  '), m('owner '), p('@api'), m('  ·  '), m('SLA '), p('3d')], W, 'r2'),
    window.row([T('  '), [' 3 ', 'c-sev-high'], m('    '), p('JWT replay across api ↔ admin (shared signing secret)'),
      m('  ·  '), m('owner '), p('@platform-sec'), m('  ·  '), m('SLA '), p('5d')], W, 'r3'),
    window.row([T('  '), [' 4 ', 'c-sev-high'], m('    '), p('Plaintext PII at db→s3 boundary'),
      m('  ·  '), m('owner '), p('@data-platform'), m('  ·  '), m('SLA '), p('7d')], W, 'r4'),
    window.row([T('  '), [' 5 ', 'c-sev-high'], m('    '), p('Shell exec from cron payload (worker.py:213)'),
      m('  ·  '), m('owner '), p('@worker'), m('  ·  '), m('SLA '), p('5d')], W, 'r5'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('NUMBERS', W, 's3'),
    window.row([T('   '), m('issues       '), p('9 modeled'), m('  ·  '), p('38 findings'), m('  ·  '), p('4 verified'), m('  ·  '), p('2 patched')], W, 'n1'),
    window.row([T('   '), m('time-on-risk '), m('mean '), p('11h'), m('  ·  '), m('p95 '), p('72h'), m('  ·  '), m('SLA breaches '), [' 0 ', 'c-success']], W, 'n2'),
    window.row([T('   '), m('regression   '), p('1'), m(' since v1.0.0 ('), p('F-0014'), m(' shell-exec)')], W, 'n3'),
    window.row([T('   '), m('coverage     '), m('apps/api '), p('98%'), m(' · apps/web '), p('92%'), m(' · libs/ '), p('86%'), m(' · jobs/ '), p('74%')], W, 'n4'),
    window.blankRow(W, 'b5'),
    window.sectionHeader('RECOMMENDED NEXT', W, 's4'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('/use verify F-0012'), m(' confirm refund-bot reach (still un-verified)')], W, 'n5'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('/use patch F-0001'), m(' staged sqlx::query! switch')], W, 'n6'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('/use threat-model'), m(' apply v4 (split jwt signing keys)')], W, 'n7'),
    window.blankRow(W, 'b6'),
    window.logLine('flow','14:27:01',[m(' '), a('/threats apply'), m(' to commit  ·  '), a('/show story'), m(' for the narrated read')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /threats summary">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'threat-model', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/threats summary · 2 blockers · 5 mediums', findings: 38,
        promptModule: 'threat-model',
        keybinds: [['/threats','dfd|stride|stories|scope'],['/use','verify|patch'],['/threats apply','commit']],
      })}
    </window.TermFrame>
  );
}
window.ThreatSummaryView = ThreatSummaryView;
