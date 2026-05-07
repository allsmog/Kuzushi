// Carlini-style threat-hunt — IN PROGRESS. Hypothesis 2 partway through;
// hypothesis 3 not yet started; budget ticking.

function CarliniInProgressView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  const cursor = (
    <span style={{ background: 'var(--t-primary)', color: 'var(--term-bg)' }}>{' '}</span>
  );

  const lines = [
    window.logLine('in', '14:44:02', [m(' /use '), a('carlini-threat-hunt')], W, 'l1'),
    window.logLine('in', '14:44:11', [m(' /run '), a('--budget 25 --depth aggressive')], W, 'l2'),
    window.logLine('run', '14:44:11', [m(' carlini-threat-hunt · adversarial walk over '), p('612'), m(' indexed files')], W, 'l3'),
    window.blankRow(W, 'b1'),

    window.sectionHeader('HYPOTHESIS 1 — auth boundary leaks via webhook replays', W, 'h1'),
    window.logLine('agent', '14:44:14', [m(' picking webhook handlers ('), p('/webhooks/stripe'), m(', '), p('/webhooks/segment'), m(')')], W, 'h1-1'),
    window.logLine('flow',  '14:44:18', [m(' tracing replay-protection \u2014 looking for per-event idempotency key')], W, 'h1-2'),
    window.logLine('find',  '14:44:23', [
      [' stripe handler trusts ', 'c-primary'],
      ['Stripe-Signature', 'c-warn'],
      [' but does not pin secret per env', 'c-primary'],
    ], W, 'h1-3'),
    window.logLine('flow',  '14:44:23', [
      [' staging key replays into production', 'c-danger'],
    ], W, 'h1-3b'),
    window.logLine('ok', '14:44:24', [m(' h1 confirmed · '), w('confidence 0.82')], W, 'h1-end'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('HYPOTHESIS 2 — prompt-injection through agent memory', W, 'h2'),
    window.logLine('agent', '14:44:31', [m(' concierge eats user reviews into pgvector \u2014 does retrieval feed system prompt?')], W, 'h2-1'),
    window.logLine('flow',  '14:44:34', [m(' walking '), p('apps/web/agents/concierge.ts'), m(' \u2192 '), p('lib/memory/recall.ts')], W, 'h2-2'),
    window.logLine('flow',  '14:44:36', [m(' read_file '), p('lib/memory/recall.ts:1-180')], W, 'h2-3'),
    // streaming line — agent mid-thought, cursor at end
    <span className="row" key="stream">
      <span>{' '}</span>
      <span className="c-subtle">14:44:38</span>
      <span>{' '}</span>
      <span className="c-accent">{' ◆ '}</span>
      <span className="c-primary">{'top-k recall concatenated '}</span>
      <span className="c-warn">{'before'}</span>
      <span className="c-primary">{' system prompt — drafting PoC'}</span>
      {cursor}
    </span>,
    window.blankRow(W, 'b3'),

    window.sectionHeader('HYPOTHESIS 3 — model-supply-chain (queued)', W, 'h3'),
    window.row([T('   '), m('   not yet started · waiting on h2 to settle')], W, 'h3-q'),
    window.blankRow(W, 'b4'),

    window.logLine('log', '14:44:38', [
      m(' budget '), p('11'), m('/'), p('25'), m(' calls used · '), p('2'), m(' more hypotheses queued'),
    ], W, 'budget'),
  ];

  const customStrip = window.row([
    [' ', null],
    ['KUZUSHI', 'c-heading'], ['  ', null],
    ['target ', 'c-muted'], ['~/work/acme-checkout', 'c-primary'], ['  ', null],
    ['module ', 'c-muted'], ['carlini-threat-hunt', 'c-accent'], ['  ', null],
    ['stage ', 'c-muted'], ['⠾ hunting h2 0:27', 'c-warn'], ['  ', null],
    ['cost ', 'c-muted'], ['$0.62', 'c-primary'],
  ], W, 'strip');

  return (
    <window.TermFrame title="kuzushi · carlini-threat-hunt · h2 in flight">
      {customStrip}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'carlini · h1 done · h2 running · h3 queued', findings: 1,
        promptModule: 'carlini-threat-hunt',
        keybinds: [
          ['Ctrl+C', 'cancel'], ['/pause', 'halt after h2'],
          ['/show', 'reasoning trace'], ['/skip', 'h2 → h3'],
        ],
      })}
    </window.TermFrame>
  );
}

window.CarliniInProgressView = CarliniInProgressView;
