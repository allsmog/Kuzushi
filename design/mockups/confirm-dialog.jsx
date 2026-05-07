// confirm dialog · destructive · network · fs:write.

function ConfirmDialogView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function box(title, glyph, color, rows) {
    const out = [];
    out.push(window.row([T('   '), ['┌─ ', 'c-subtle'], [glyph + ' ' + title + ' ', color],
      ['─'.repeat(W - 6 - 4 - title.length - 2), 'c-subtle'], ['┐', 'c-subtle']], W, title+'top'));
    for (const r of rows) {
      const padded = (r + ' '.repeat(W - 8)).slice(0, W - 8);
      out.push(window.row([T('   '), ['│ ', 'c-subtle'], [padded, 'c-primary'], [' │', 'c-subtle']], W, title+r));
    }
    out.push(window.row([T('   '), ['└', 'c-subtle'], ['─'.repeat(W - 6), 'c-subtle'], ['┘', 'c-subtle']], W, title+'bot'));
    return out;
  }

  const lines = [
    window.logLine('agent','14:38:01',[m(' agent wants to dispatch '), p('sandbox:run curl https://refund.acme/api/internal/balances')], W, 'l1'),
    window.blankRow(W, 'b1'),
    ...box('CONFIRM · network egress', '⚠', 'c-warn', [
      ' tool          sandbox:run',
      ' verb          curl',
      ' target        https://refund.acme/api/internal/balances',
      ' allowlist     refund.acme is on the project allowlist (matched: refund.acme)',
      ' actor         attacker · anthropic:claude-sonnet-4',
      ' rationale     "verify F-0012 reachability — read-only GET, expects 401"',
      ' egress bytes  estimate <2 KB · 1 RTT',
    ]),
    window.blankRow(W, 'b2'),
    window.row([T('   '), [' y ', 'c-success'], m(' allow once · '), [' Y ', 'c-success'],
      m(' allow + remember for this run · '), [' n ', 'c-danger'],
      m(' deny once · '), [' N ', 'c-danger'], m(' deny + add to denylist')], W, 'k1'),
    window.blankRow(W, 'b3'),
    ...box('REFUSED · destructive verb', '✗', 'c-danger', [
      ' tool          shell:run',
      ' verb          rm -rf .git',
      ' actor         attacker',
      ' rule          destructive verb on host fs · ALWAYS refused',
      ' override      none — this gate is unconditional',
    ]),
    window.blankRow(W, 'b4'),
    ...box('CONFIRM · fs:write outside .kuzushi/', '⚠', 'c-warn', [
      ' tool          fs:write',
      ' path          apps/web/agents/concierge.ts',
      ' diff          +6 / -2 lines · same bytes as approved patch F-0002',
      ' actor         patcher',
      ' rationale     "applying staged patch · checks 4/5 pass · verify pending"',
      ' undo          .kuzushi/runs/r-2113/snapshots/concierge.ts.bak',
    ]),
    window.blankRow(W, 'b5'),
    window.row([T('   '), [' i ', 'c-accent'], m('  approvals are recorded in '), p('.kuzushi/v2/audit.log'),
      m(' · attach reason w/ '), a('y -- "tail of refund spike investigation"')], W, 'i1'),
  ];

  return (
    <window.TermFrame title="kuzushi · approvals">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'sandbox', cost: '$0.31' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'pending: 2 confirms · 1 unconditional refusal', findings: 38,
        keybinds: [['y/n','once'],['Y/N','remember'],['y -- "reason"','annotate']],
      })}
    </window.TermFrame>
  );
}
window.ConfirmDialogView = ConfirmDialogView;
