// SAST view (in-progress) — umbrella scan partway through.
// agentic-sast still tracing; triage hasn't started; spinner on the status
// strip; last log line ends with a streaming cursor.

function SastInProgressView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function bar(label, done, total, status, color = 'c-success') {
    const width = 24;
    const pct = total === 0 ? 0 : Math.min(1, done / total);
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
      [status, color === 'c-warn' ? 'c-warn' : color === 'c-danger' ? 'c-danger' : 'c-success'],
    ];
  }

  function partialFinding(alias, sev, name, where) {
    const sevMap = { critical: 'c-sev-critical', high: 'c-sev-high', medium: 'c-sev-medium', low: 'c-sev-low' };
    return [
      [' ', null],
      [alias, 'c-accent'],
      ['  ', null],
      [(sev.toUpperCase() + ' '.repeat(10)).slice(0, 9), sevMap[sev]],
      [(name + ' '.repeat(60)).slice(0, 50), 'c-primary'],
      [where, 'c-muted'],
    ];
  }

  // streaming cursor (block) — same color as primary, on dark bg
  const cursor = (
    <span style={{ background: 'var(--t-primary)', color: 'var(--term-bg)' }}>{' '}</span>
  );

  const lines = [
    window.logLine('in', '14:31:55', [m(' /scan · plan confirmed')], W, 'l1'),
    window.logLine('run', '14:31:55', [m(' sast:scan · tasks '), a('semgrep, secret-scan, agentic-sast'), m(' · triage on')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('semgrep             ', 612, 612, 'done · 18 raw hits', 'c-success')], W, 'p1'),
    window.row([T('   '), ...bar('secret-scan         ', 1284, 1284, 'done · 0 hits',     'c-success')], W, 'p2'),
    window.row([T('   '), ...bar('agentic-sast        ', 38,  120, 'tracing dataflows…', 'c-warn')], W, 'p3'),
    window.row([T('   '), ...bar('triage (post-scan)  ', 0,   18,  'queued',             'c-subtle')], W, 'p4'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('FINDINGS · 4 raw · triage queued', W, 'sec1'),
    window.row(partialFinding('F-0001', 'critical', 'sql injection via order_id concatenation',     'apps/api/orders.rs:142'), W, 'f1'),
    window.row(partialFinding('F-0002', 'critical', 'prompt-injection sink — model reads user body','apps/web/agents/concierge.ts:88'), W, 'f2'),
    window.row(partialFinding('F-0003', 'high',     'jwt verify with alg=none accepted',            'apps/api/auth/jwt.rs:54'), W, 'f3'),
    window.row(partialFinding('F-0004', 'high',     'shell exec from cron payload',                 'jobs/worker.py:213'), W, 'f4'),
    window.blankRow(W, 'b3'),

    window.logLine('flow', '14:32:14', [m(' agentic-sast · seed F-0002 · expanding variant set …')], W, 'fl1'),
    window.logLine('flow', '14:32:21', [m(' grep '), p('"buildPrompt", "messages.push"'), m(' → 14 hits across 6 files')], W, 'fl2'),
    window.logLine('flow', '14:32:27', [m(' read_file '), p('apps/web/agents/refund-bot.ts:60-160')], W, 'fl3'),
    window.logLine('agent', '14:32:31', [
      [' refund-bot builds its system prompt from ', 'c-primary'],
      ['ticket.subject', 'c-warn'],
      [' \u2014 likely variant\u2026', 'c-primary'],
    ], W, 'fl4'),
    // Live streaming line: glyph, label, partial words, then a blinking cursor
    <span className="row" key="stream">
      <span>{' '}</span>
      <span className="c-subtle">14:32:33</span>
      <span>{' '}</span>
      <span className="c-muted">{' … '}</span>
      <span className="c-muted">{'taint-step '}</span>
      <span className="c-primary">{'ticket.subject → openai.chat '}</span>
      {cursor}
    </span>,
  ];

  // Spinner glyph in the status strip (replaces ✓ for ctx, but cleaner to put
  // the spinner in the stage). We override the strip with a custom build so
  // the running indicator reads correctly.
  const customStrip = window.row([
    [' ', null],
    ['KUZUSHI', 'c-heading'], ['  ', null],
    ['target ', 'c-muted'], ['~/work/acme-checkout', 'c-primary'], ['  ', null],
    ['module ', 'c-muted'], ['sast', 'c-accent'], ['  ', null],
    ['stage ', 'c-muted'], ['⠿ running 0:38', 'c-warn'], ['  ', null],
    ['cost ', 'c-muted'], ['$0.21', 'c-primary'],
  ], W, 'strip');

  return (
    <window.TermFrame title="kuzushi · sast:scan · in progress">
      {customStrip}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'sast:scan · agentic 32% · triage queued', findings: 4,
        promptModule: 'sast',
        keybinds: [
          ['Ctrl+C', 'cancel'], ['/pause', 'halt'],
          ['/findings', 'live'], ['/show', 'trace'],
        ],
      })}
    </window.TermFrame>
  );
}

window.SastInProgressView = SastInProgressView;
