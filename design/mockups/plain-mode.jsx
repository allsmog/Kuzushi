// plain mode · interactive workflow rejection

function PlainModeView() {
  const W = window.W120;

  // No statusStrip, no fancy rules, no footer. Just deterministic lines.
  const lines = [
    window.row([['kuzushi 0.18.2  --plain  pid 41912', 'c-muted']], W, 'h1'),
    window.row([['target ', 'c-muted'], ['none', 'c-warn'],
      ['  mode ', 'c-muted'], ['scripted shell', 'c-primary']], W, 'h2'),
    window.blankRow(W, 'b1'),
    window.row([['[15:32:01] ', 'c-muted'], ['cmd   ', 'c-muted'], ['/scan', 'c-primary']], W, 'l1'),
    window.row([['[15:32:01] ', 'c-muted'], ['error ', 'c-danger'], ['/scan is an interactive TUI workflow', 'c-primary']], W, 'l2'),
    window.row([['[15:32:01] ', 'c-muted'], ['next  ', 'c-muted'], ['for scripts use kuzushi scan <target>', 'c-accent']], W, 'l3'),
    window.row([['[15:32:01] ', 'c-muted'], ['next  ', 'c-muted'], ['or kuzushi --target <target> run sast:scan', 'c-accent']], W, 'l4'),
    window.row([['[15:32:01] ', 'c-muted'], ['done  ', 'c-danger'], ['/scan exit=1 · worker=not started · run=none · run artifacts=none', 'c-primary']], W, 'l5'),
    window.blankRow(W, 'b2'),
    window.row([['# same deterministic rejection', 'c-muted']], W, 'c1'),
    window.row([['  /map  /review  /prove  /fix  /full [target]  /pipeline [target]', 'c-primary']], W, 'c2'),
    window.row([['  each exits 1 · no planning picker · no worker · no run artifacts', 'c-muted']], W, 'c3'),
    window.blankRow(W, 'b3'),
    window.row([['# behavior · plain mode', 'c-muted']], W, 'p1'),
    window.row([['  no statusbar · no footer · no spinners · no hot-keys · no agent prose', 'c-muted']], W, 'p2'),
    window.row([['  phase and guided commands need confirmation surfaces available only in the interactive TUI', 'c-muted']], W, 'p3'),
    window.row([['  headless: ', 'c-muted'], ['kuzushi scan <target>', 'c-accent'],
      [' · one tool: ', 'c-muted'], ['kuzushi --target <target> run sast:scan', 'c-accent']], W, 'p4'),
  ];

  return (
    <window.TermFrame title="kuzushi --plain · workflow rejected">
      <span className="row c-subtle">{'─'.repeat(120)}</span>
      <span className="row">{' '.repeat(120)}</span>
      {lines}
      <span className="row">{' '.repeat(120)}</span>
    </window.TermFrame>
  );
}
window.PlainModeView = PlainModeView;
