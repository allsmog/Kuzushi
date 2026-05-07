// /threats stories — narrative scenarios.

function ThreatStoriesView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function story(idx, title, sev, body, fork) {
    const sMap = { critical: 'c-sev-critical', high: 'c-sev-high', medium: 'c-sev-medium', low: 'c-sev-low' };
    return [
      window.row([T(' '), [`#${idx}  `, 'c-subtle'], [(sev.toUpperCase() + ' '.repeat(10)).slice(0, 9), sMap[sev]],
                 [' ', null], [title, 'c-heading']], W, `t${idx}`),
      window.row([T('     '), [body, 'c-primary']], W, `b${idx}`),
      window.row([T('     '), m('→ '), [fork, 'c-warn']], W, `f${idx}`),
      window.blankRow(W, `s${idx}`),
    ];
  }

  const lines = [
    window.logLine('in','14:24:18',[m(' /threats '), a('stories')], W, 'l1'),
    window.blankRow(W, 'b1'),
    ...story(1, 'Refund-bot promotes a refund for an attacker', 'critical',
      'Attacker submits a review whose body splices the concierge agent\'s sysmsg, escalates context, and instructs the refund-bot to issue a $9999.99 refund to a controlled bank account. No human is in the loop on refunds < $200, but the prompt-injection can override the threshold.',
      'fork: F-0002 → F-0012  ·  blast radius: any reviewer-tier user'),
    ...story(2, 'Insider exfiltrates s3://invoices via worker-pool', 'critical',
      'A disgruntled SRE with worker-pool access reads plaintext PII from s3, transcripts to a personal bucket. AMQP messages aren\'t signed, so tampering is undetectable in audit.',
      'fork: I-1, T-1  ·  blast radius: every order in the last 18 months'),
    ...story(3, 'JWT replay across api ↔ admin', 'high',
      'admin.acme-checkout.com signs and verifies with the same secret as api.acme-checkout.com — and there is no aud claim. A token issued to a regular user can be replayed against admin endpoints that do not separately re-authorize.',
      'fork: S-1, E-1  ·  blast radius: any authenticated user who reaches admin'),
    ...story(4, 'Catastrophic regex DoS on /search', 'medium',
      'A request-supplied query is compiled into a regex with no length cap, leading to catastrophic backtracking. A handful of crafted requests pin a worker thread, degrading the search tier.',
      'fork: D-1, F-0008  ·  blast radius: search tier (3 workers)'),
    window.logLine('flow','14:24:18',[
      m(' '), a('/threats stride'), m(' for the table  ·  '), a('/use randori'), m(' to enrich with ATT&CK + KEV'),
    ], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /threats stories">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'threat-model', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/threats stories · 4 scenarios', findings: 9,
        promptModule: 'threat-model',
        keybinds: [['j/k','story'],['/threats','dfd|stride|scope'],['/use','randori']],
      })}
    </window.TermFrame>
  );
}
window.ThreatStoriesView = ThreatStoriesView;
