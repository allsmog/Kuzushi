// /use deep-auditor — long-form ToB-style narrative auditor.

function DeepAuditorView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function bullet(c, glyphClass, t) {
    return window.row([T('   '), [c + ' ', glyphClass || 'c-accent'], [t, 'c-primary']], W, t);
  }

  const lines = [
    window.logLine('in','15:31:00',[m(' /use '), a('deep-auditor')], W, 'l1'),
    window.logLine('in','15:31:18',[m(' /run deep-auditor:audit '), a('{"scope":"libs/payments","budget":"$3.00"}')], W, 'l2'),
    window.logLine('run','15:31:18',[m(' deep-auditor · slow + cited · h=3 · model '), p('anthropic:opus-4.5')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('PASS 1 · ARCHITECTURE READ', W, 's1'),
    bullet('▸', 'c-accent', 'libs/payments exposes 4 public types: Money, Card, Charge, Refund'),
    bullet('▸', 'c-accent', 'Money is the only one with serde::Deserialize from arbitrary input'),
    bullet('▸', 'c-accent', '6 boundary functions live in libs/payments/api.rs · 2 are async + bound to web'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('PASS 2 · SUSPICIOUS PATTERNS', W, 's2'),
    bullet('!', 'c-warn', 'libs/payments/api.rs:88 · From<f64> for Money — cents truncation possible at boundary'),
    bullet('!', 'c-warn', 'libs/payments/refund.rs:42 · Refund::issue takes &mut Charge but no idempotency key'),
    bullet('!', 'c-warn', 'libs/payments/api.rs:204 · validate_card returns bool; callers ignore the failure path'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('PASS 3 · NARRATIVE FINDINGS', W, 's3'),
    window.row([T('  '), [' 1 ', 'c-sev-high'], m('   '), p('Refund double-spend window'), m('  ·  '), p('refund.rs:42')], W, 'n1'),
    window.row([T('       '), m('Two concurrent refunds against the same Charge can both succeed in the 18ms')], W, 'n1a'),
    window.row([T('       '), m('between row read and `charge.status = Refunded` write. There is no idempotency key,')], W, 'n1b'),
    window.row([T('       '), m('and the postgres UPDATE is unconditional, so the second refund overwrites without')], W, 'n1c'),
    window.row([T('       '), m('a constraint violation. Net effect: a customer can be refunded twice.')], W, 'n1d'),
    window.row([T('       '), m('Cited: a-04 (CVE-2024-1234 race-class), libs/payments/refund.rs:42-71')], W, 'n1e'),
    window.blankRow(W, 'b4'),
    window.row([T('  '), [' 2 ', 'c-sev-medium'], m(' '), p('Money parsing accepts NaN'), m('  ·  '), p('api.rs:88')], W, 'n2'),
    window.row([T('       '), m('Money::from_f64 does no NaN check; downstream serializer renders "NaN" which the')], W, 'n2a'),
    window.row([T('       '), m('postgres NUMERIC column rejects, so the request 500s instead of 400ing — visible')], W, 'n2b'),
    window.row([T('       '), m('but a thin DoS vector if exposed at a public boundary. (Not currently exposed.)')], W, 'n2c'),
    window.blankRow(W, 'b5'),
    window.row([T('  '), [' 3 ', 'c-sev-low'], m('     '), p('validate_card return ignored'), m('  ·  '), p('api.rs:204')], W, 'n3'),
    window.row([T('       '), m('Two of three call-sites discard the return; this is a footgun, not currently')], W, 'n3a'),
    window.row([T('       '), m('exploitable because the type system bottoms out at a separate authorize() call.')], W, 'n3b'),
    window.blankRow(W, 'b6'),
    window.logLine('agent','15:33:42',[
      m(' '), [' net ', 'c-warn'], m(' 1 high (race), 1 medium (NaN), 1 low (footgun) · 12m12s · '),
      p('$2.41 / $3.00'), m(' · '), [' write findings? ', 'c-accent'],
    ], W, 'l4'),
    window.logLine('flow','15:33:42',[m(' '), a('y'), m(' promote · '), a('e'), m(' edit narrative · '), a('n'), m(' discard')], W, 'l5'),
  ];

  return (
    <window.TermFrame title="kuzushi · deep-auditor · libs/payments">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'deep-auditor', cost: '$2.41' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'deep-auditor · 3 narrative findings · 12m12s', findings: 38,
        promptModule: 'deep-auditor',
        keybinds: [['y','promote'],['e','edit'],['n','discard'],['/use patch','staged']],
      })}
    </window.TermFrame>
  );
}
window.DeepAuditorView = DeepAuditorView;
