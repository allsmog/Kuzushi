// boot splash · first-launch / cold-start

function BootSplashView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];

  // Center the kuzushi block letter art in the frame.
  const ART = [
    "  ██╗  ██╗██╗   ██╗███████╗██╗   ██╗███████╗██╗  ██╗██╗",
    "  ██║ ██╔╝██║   ██║╚══███╔╝██║   ██║██╔════╝██║  ██║██║",
    "  █████╔╝ ██║   ██║  ███╔╝ ██║   ██║███████╗███████║██║",
    "  ██╔═██╗ ██║   ██║ ███╔╝  ██║   ██║╚════██║██╔══██║██║",
    "  ██║  ██╗╚██████╔╝███████╗╚██████╔╝███████║██║  ██║██║",
    "  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝",
  ];

  function center(text, cls) {
    const pad = Math.max(0, Math.floor((W - [...text].length) / 2));
    return window.row([[' '.repeat(pad), null], [text, cls]], W, text);
  }

  function dotLine(state, label, val) {
    const map = { ok:[' ✓ ', 'c-success'], wait:[' · ', 'c-subtle'], err:[' ✗ ', 'c-danger'] };
    const inner = '  ' + label.padEnd(28, ' ') + val.padEnd(40, ' ');
    const pad = Math.max(0, Math.floor((W - inner.length - 3) / 2));
    return window.row([
      [' '.repeat(pad), null], map[state],
      [(label + ' '.repeat(28)).slice(0, 28), 'c-muted'],
      [(val + ' '.repeat(40)).slice(0, 40), 'c-primary'],
    ], W, label);
  }

  const lines = [
    window.blankRow(W, 'top1'),
    window.blankRow(W, 'top2'),
    window.blankRow(W, 'top3'),
    ...ART.map((t, i) => center(t, 'c-heading')),
    window.blankRow(W, 'sp1'),
    center('崩し  ·  break the form before the form breaks you',  'c-muted'),
    window.blankRow(W, 'sp2'),
    center('v0.18.2  ·  released 2026-04-29  ·  channel stable',   'c-subtle'),
    window.blankRow(W, 'sp3'),
    window.blankRow(W, 'sp4'),
    dotLine('ok',   'config',                  '~/.kuzushi/v2/options.toml · 12 keys · 3 overridden'),
    dotLine('ok',   'audit',                   '~/.kuzushi/v2/audit.log · chain tip cb91…02'),
    dotLine('ok',   'workspace',               'acme-checkout · main@d41a2cc · clean'),
    dotLine('ok',   'context-snapshot',        'fresh · built 11:58 · 482 files · 142 KB'),
    dotLine('ok',   'auth · openai',           'sk-…vQ8R · used 2m ago'),
    dotLine('ok',   'auth · anthropic',        'sk-ant-…pZ12 · used 14h ago'),
    dotLine('err',  'auth · github',           'expired 3d ago · run /auth login github'),
    dotLine('wait', 'kb · advisories',         '… pulling kev + nvd · 41 new'),
    dotLine('wait', 'plugins',                 '… enumerating ~/.kuzushi/v2/plugins'),
    window.blankRow(W, 'sp5'),
    center('press ? for help · type /catalog for the menu · /doctor if anything looks off', 'c-muted'),
    window.blankRow(W, 'sp6'),
    center('ctrl-c quits · config + history persist across sessions', 'c-subtle'),
  ];

  return (
    <window.TermFrame title="kuzushi · boot">
      <span className="row c-subtle">{'─'.repeat(120)}</span>
      <span className="row">{' '.repeat(120)}</span>
      {lines}
      <span className="row">{' '.repeat(120)}</span>
    </window.TermFrame>
  );
}
window.BootSplashView = BootSplashView;
