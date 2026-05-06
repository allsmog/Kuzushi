// Carlini-style threat-hunt view — adversarial walk over the codebase, with
// the agent narrating its reasoning trace as it goes.

function CarliniView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('in', '14:44:02', [m(' /use '), a('carlini-threat-hunt')], W, 'l1'),
    window.logLine('in', '14:44:11', [m(' /run '), a('--budget 25 --depth aggressive')], W, 'l2'),
    window.logLine('run', '14:44:11', [m(' carlini-threat-hunt · adversarial walk over '), p('612'), m(' indexed files')], W, 'l3'),
    window.blankRow(W, 'b1'),

    window.sectionHeader('HYPOTHESIS 1 — auth boundary leaks via webhook replays', W, 'h1'),
    window.logLine('agent', '14:44:14', [m(' picking webhook handlers as starting set ('), p('/webhooks/stripe'), m(', '), p('/webhooks/segment'), m(')')], W, 'h1-1'),
    window.logLine('flow',  '14:44:18', [m(' tracing replay-protection — looking for a per-event idempotency key')], W, 'h1-2'),
    window.logLine('find',  '14:44:23', [
      [' stripe handler trusts ', 'c-primary'],
      ['Stripe-Signature', 'c-warn'],
      [' but does not pin secret per env', 'c-primary'],
    ], W, 'h1-3'),
    window.logLine('flow',  '14:44:23', [
      [' staging key replays into production', 'c-danger'],
    ], W, 'h1-3b'),
    window.logLine('agent', '14:44:24', [m(' ['), w('confidence 0.82'), m('] cross-checking '), p('apps/api/webhooks/stripe.rs'), m(' vs. '), p('infra/secrets.tf')], W, 'h1-4'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('HYPOTHESIS 2 — prompt-injection through agent memory', W, 'h2'),
    window.logLine('agent', '14:44:31', [m(' our own concierge agent eats user reviews into pgvector — does retrieval ever feed system prompt?')], W, 'h2-1'),
    window.logLine('flow',  '14:44:34', [m(' walking '), p('apps/web/agents/concierge.ts'), m(' → '), p('lib/memory/recall.ts'), m(' → system msg builder')], W, 'h2-2'),
    window.logLine('find',  '14:44:39', [
      [' top-k recall is concatenated ', 'c-primary'],
      ['before', 'c-warn'],
      [' the system prompt — ', 'c-primary'],
      ['user-controlled review text becomes instructions', 'c-danger'],
    ], W, 'h2-3'),
    window.logLine('agent', '14:44:40', [m(' ['), w('confidence 0.91'), m('] crafted PoC: a 12-word review that flips the agent into refund-approval mode')], W, 'h2-4'),
    window.logLine('log',   '14:44:40', [m(' artifact saved: '), p('.kuzushi/runs/2026-05-06T14-44/poc-h2.txt')], W, 'h2-5'),
    window.blankRow(W, 'b3'),

    window.sectionHeader('HYPOTHESIS 3 — model-supply-chain · openai key in build artifact', W, 'h3'),
    window.logLine('agent', '14:44:48', [m(' scanning build outputs ('), p('dist/'), m(', '), p('docker layers'), m(') for embedded creds — agentic, not regex')], W, 'h3-1'),
    window.logLine('flow',  '14:44:55', [m(' inspected 41 layers · 0 plaintext keys · 1 encoded blob warrants follow-up')], W, 'h3-2'),
    window.logLine('agent', '14:45:01', [m(' ['), m('confidence 0.18'), m('] inconclusive — recommend '), a('/use secret-scan'), m(' over '), p('docker-archive')], W, 'h3-3'),
    window.blankRow(W, 'b4'),

    window.logLine('ok', '14:45:02', [
      [' hunt complete · ', 'c-muted'],
      ['2', 'c-primary'], [' confirmed leads · ', 'c-muted'],
      ['1', 'c-primary'], [' inconclusive · budget ', 'c-muted'],
      ['18', 'c-primary'], ['/25 calls used', 'c-muted'],
    ], W, 'l-end'),
    window.logLine('log', '14:45:02', [m(' promote leads to findings: '), a('/promote h1 h2 --severity critical')], W, 'l-cta'),
  ];

  return (
    <window.TermFrame title="kuzushi · carlini-threat-hunt · adversarial walk">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'carlini-threat-hunt', cost: '$1.07' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end-1')}
      {window.footer({
        stage: 'carlini-threat-hunt (done) · 18/25 budget', findings: 13,
        promptModule: 'carlini-threat-hunt',
        keybinds: [
          ['/promote', 'h1 h2'], ['/show', 'reasoning trace'],
          ['/use', 'verify h2'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.CarliniView = CarliniView;
