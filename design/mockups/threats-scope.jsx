// /threats scope — scope and assumptions.

function ThreatScopeView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function bullet(c, t) { return window.row([T('   '), [c + ' ', 'c-accent'], [t, 'c-primary']], W, t); }

  const lines = [
    window.logLine('in','14:25:42',[m(' /threats '), a('scope')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('IN-SCOPE', W, 's1'),
    bullet('▸', 'apps/api  · Rust · production traffic-bearing api edge'),
    bullet('▸', 'apps/web  · TS · public marketing + agentic flows (concierge, refund-bot)'),
    bullet('▸', 'libs/payments · shared payment primitives (PCI-adjacent)'),
    bullet('▸', 'jobs/      · cron + amqp consumers'),
    bullet('▸', 'infra/admin · admin subdomain (jwt secret co-located w/ api)'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('OUT-OF-SCOPE', W, 's2'),
    bullet('·', 'docs/      · static markdown'),
    bullet('·', 'scripts/   · operator scripts; assumed run by humans only'),
    bullet('·', 'tools/     · dev-only utilities; not deployed'),
    bullet('·', 'third-party SaaS (mailgun, stripe) — modeled at boundaries, not internals'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('TRUST BOUNDARIES · 9', W, 's3'),
    window.row([T('   '), m(' '), [' ▸ ', 'c-accent'], p('user'), m(' → '), p('nginx'), m(' (https · TLS terminated at LB)')], W, 'b1b'),
    window.row([T('   '), m(' '), [' ▸ ', 'c-accent'], p('nginx'), m(' → '), p('apps/api'), m(' (bearer-jwt; no aud)')], W, 'b2b'),
    window.row([T('   '), m(' '), [' ▸ ', 'c-accent'], p('apps/api'), m(' → '), p('postgres'), m(' (connection pool; sqlx)')], W, 'b3b'),
    window.row([T('   '), m(' '), [' ▸ ', 'c-accent'], p('apps/api'), m(' → '), p('rabbitmq'), m(' (amqp; unsigned)')], W, 'b4b'),
    window.row([T('   '), m(' '), [' ▸ ', 'c-accent'], p('worker-pool'), m(' → '), p('s3 (us-east)'), m(' (sigv4; bucket policy)')], W, 'b5b'),
    window.row([T('   '), m(' '), [' ▸ ', 'c-accent'], p('apps/web'), m(' → '), p('LLM provider'), m(' (per-tenant key)')], W, 'b6b'),
    window.row([T('   '), m(' '), [' ▸ ', 'c-accent'], p('admin.acme'), m(' ↔ '), p('api.acme'), m(' (shared jwt secret · '), [' boundary leak ', 'c-warn'], m(')')], W, 'b7b'),
    window.row([T('   '), m(' '), [' ▸ ', 'c-accent'], p('reviewer'), m(' → '), p('refund-bot'), m(' (review.body reaches sysmsg)')], W, 'b8b'),
    window.row([T('   '), m(' '), [' ▸ ', 'c-accent'], p('developer'), m(' → '), p('CI'), m(' (pinned + signed actions)')], W, 'b9b'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('ASSUMPTIONS', W, 's4'),
    bullet('?', 'TLS is correctly terminated at the LB · we do not model TLS bugs'),
    bullet('?', 'PG superuser access is human-gated via SSO · not threat-modeled here'),
    bullet('?', 'Internal PKI rotates monthly · model assumes valid certs throughout'),
    bullet('!', 'Mailgun cname is dangling — we DO model this (S-2)'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','14:25:42',[m(' '), a('/threats summary'), m(' to see the executive view  ·  '), a('/threats apply'), m(' to commit')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /threats scope">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'threat-model', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/threats scope · 9 boundaries', findings: 9,
        promptModule: 'threat-model',
        keybinds: [['/threats','dfd|stride|stories|summary'],['/threats apply','commit']],
      })}
    </window.TermFrame>
  );
}
window.ThreatScopeView = ThreatScopeView;
