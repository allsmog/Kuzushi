// plain mode · CI-friendly stripped-down

function PlainModeView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];

  // No statusStrip, no fancy rules, no footer. Just lines.
  const lines = [
    window.row([['kuzushi 0.18.2  --plain  pid 41912', 'c-muted']], W, 'h1'),
    window.row([['target ', 'c-muted'], ['~/work/acme-checkout', 'c-primary'],
      ['  ws ', 'c-muted'], ['acme-checkout', 'c-primary'],
      ['  branch ', 'c-muted'], ['main@d41a2cc', 'c-primary'],
      ['  actor ', 'c-muted'], ['attacker · openai:gpt-4.1', 'c-primary']], W, 'h2'),
    window.blankRow(W, 'b1'),
    window.row([['[15:32:01] ', 'c-muted'], ['cmd  ', 'c-muted'], ['/scan', 'c-primary']], W, 'l1'),
    window.row([['[15:32:01] ', 'c-muted'], ['run  ', 'c-muted'], ['sast:scan tasks=semgrep,secret-scan,agentic-sast', 'c-primary']], W, 'l2'),
    window.row([['[15:32:08] ', 'c-muted'], ['ok   ', 'c-success'], ['semgrep done · 612/612 · 18 hits', 'c-primary']], W, 'l3'),
    window.row([['[15:32:14] ', 'c-muted'], ['ok   ', 'c-success'], ['secret-scan done · 1284/1284 · 0 hits', 'c-primary']], W, 'l4'),
    window.row([['[15:33:42] ', 'c-muted'], ['flow ', 'c-muted'], ['agentic-sast · 87/120 · tracing dataflows', 'c-primary']], W, 'l5'),
    window.row([['[15:33:42] ', 'c-muted'], ['find ', 'c-warn'], ['F-0001 critical apps/api/orders.rs:142 sql-injection', 'c-primary']], W, 'l6'),
    window.row([['[15:33:42] ', 'c-muted'], ['find ', 'c-warn'], ['F-0002 critical apps/web/agents/concierge.ts:88 prompt-injection', 'c-primary']], W, 'l7'),
    window.row([['[15:33:42] ', 'c-muted'], ['find ', 'c-warn'], ['F-0003 high     apps/api/auth/jwt.rs:54 alg=none accepted', 'c-primary']], W, 'l8'),
    window.row([['[15:33:42] ', 'c-muted'], ['find ', 'c-warn'], ['F-0004 high     jobs/worker.py:213 shell exec from cron', 'c-primary']], W, 'l9'),
    window.row([['[15:33:42] ', 'c-muted'], ['find ', 'c-warn'], ['F-0005 high     apps/web/server.ts:301 path traversal /assets', 'c-primary']], W, 'l10'),
    window.row([['[15:33:51] ', 'c-muted'], ['ok   ', 'c-success'], ['agentic-sast done · 120/120 · 7 findings', 'c-primary']], W, 'l11'),
    window.row([['[15:34:08] ', 'c-muted'], ['flow ', 'c-muted'], ['triage on · floor=high · 11 to classify', 'c-primary']], W, 'l12'),
    window.row([['[15:34:24] ', 'c-muted'], ['ok   ', 'c-success'], ['triage done · 11 classified · 7 promoted', 'c-primary']], W, 'l13'),
    window.row([['[15:34:24] ', 'c-muted'], ['done ', 'c-success'], ['/scan exit=0 · cost=$0.41 · findings=11 · run=r-2118', 'c-primary']], W, 'l14'),
    window.blankRow(W, 'b2'),
    window.row([['# ci-summary', 'c-muted']], W, 'c1'),
    window.row([['{', 'c-subtle']], W, 'c2'),
    window.row([['  ', null], ['"run":', 'c-muted'], [' ', null], ['"r-2118"', 'c-primary'], [',', 'c-subtle']], W, 'c3'),
    window.row([['  ', null], ['"target":', 'c-muted'], [' ', null], ['"acme-checkout@d41a2cc"', 'c-primary'], [',', 'c-subtle']], W, 'c4'),
    window.row([['  ', null], ['"findings":', 'c-muted'], [' {', 'c-subtle'],
      ['"critical":', 'c-muted'], ['2', 'c-primary'], [',', 'c-subtle'],
      ['"high":', 'c-muted'], ['5', 'c-primary'], [',', 'c-subtle'],
      ['"medium":', 'c-muted'], ['3', 'c-primary'], [',', 'c-subtle'],
      ['"low":', 'c-muted'], ['1', 'c-primary'], ['},', 'c-subtle']], W, 'c5'),
    window.row([['  ', null], ['"new_critical":', 'c-muted'], [' ', null], ['1', 'c-primary'],
      [' ', null], ['# F-0012 (refund-bot)', 'c-muted']], W, 'c6'),
    window.row([['  ', null], ['"verified_fixed":', 'c-muted'], [' ', null], ['1', 'c-primary'],
      [' ', null], ['# F-0002', 'c-muted']], W, 'c7'),
    window.row([['  ', null], ['"cost_usd":', 'c-muted'], [' ', null], ['0.41', 'c-primary'], [',', 'c-subtle']], W, 'c8'),
    window.row([['  ', null], ['"exit":', 'c-muted'], [' ', null], ['0', 'c-success']], W, 'c9'),
    window.row([['}', 'c-subtle']], W, 'c10'),
    window.blankRow(W, 'b3'),
    window.row([['# behavior · plain mode', 'c-muted']], W, 'p1'),
    window.row([['  no statusbar  ·  no footer  ·  no spinners  ·  no hot-keys  ·  no agent prose', 'c-muted']], W, 'p2'),
    window.row([['  exit code is the gate · ', 'c-muted'], ['1', 'c-danger'],
      [' if any new critical or high · ', 'c-muted'],
      ['2', 'c-warn'], [' if budget exceeded · ', 'c-muted'],
      ['3', 'c-warn'], [' if a refusal blocked work', 'c-muted']], W, 'p3'),
    window.row([['  enable with ', 'c-muted'], ['--plain', 'c-accent'],
      [' or env ', 'c-muted'], ['KUZUSHI_PLAIN=1', 'c-primary'],
      [' · auto-on if ', 'c-muted'], ['stdout', 'c-primary'],
      [' is not a tty', 'c-muted']], W, 'p4'),
  ];

  return (
    <window.TermFrame title="kuzushi --plain · ci">
      <span className="row c-subtle">{'─'.repeat(120)}</span>
      <span className="row">{' '.repeat(120)}</span>
      {lines}
      <span className="row">{' '.repeat(120)}</span>
    </window.TermFrame>
  );
}
window.PlainModeView = PlainModeView;
