// Shared TUI primitives — terminal frame, row builders, glyphs, color spans.
// Used by every view file in mockups/.

const W120 = 120;

// Pad-to-width helper that respects already-built JSX width.
// Strings only; we count visible chars as 1 cell each (no double-width here).
function padTo(text, width) {
  const len = [...text].length;
  return text + ' '.repeat(Math.max(0, width - len));
}

// Build a row from segment tuples [text, className].
// Auto-pads the trailing space to the requested width.
function row(segments, width = W120, key) {
  const total = segments.reduce((n, [t]) => n + [...t].length, 0);
  const pad = ' '.repeat(Math.max(0, width - total));
  return (
    <span className="row" key={key}>
      {segments.map(([t, c], i) =>
        c ? <span key={i} className={c}>{t}</span> : <span key={i}>{t}</span>
      )}
      {pad ? <span>{pad}</span> : null}
    </span>
  );
}

function blankRow(width = W120, key) {
  return <span className="row" key={key || ''}>{' '.repeat(width)}</span>;
}

function ruleRow(width = W120, key) {
  return <span className="row c-subtle" key={key || ''}>{'─'.repeat(width)}</span>;
}

// Top status strip — one line, common across every view.
// strip({target, ctx, model, module, cost}) -> JSX row
function statusStrip(opts) {
  const { target, ctx = 'fresh (3m ago)', model = 'openai:gpt-4.1', module: mod = '—', cost = '$0.00' } = opts;
  return row([
    [' ', null],
    ['KUZUSHI', 'c-heading'],
    ['  ', null],
    ['target ', 'c-muted'],
    [target, 'c-primary'],
    ['  ', null],
    ['ctx ', 'c-muted'],
    ['✓ ', 'c-success'],
    [ctx, 'c-primary'],
    ['  ', null],
    ['model ', 'c-muted'],
    [model, 'c-primary'],
    ['  ', null],
    ['module ', 'c-muted'],
    [mod, mod === '—' ? 'c-muted' : 'c-accent'],
    ['  ', null],
    ['cost ', 'c-muted'],
    [cost, 'c-primary'],
  ], W120, 'strip');
}

// Console-line glyph + timestamp prefix. Mirrors Claude Code's bullet list
// but keeps its own glyphs:
//   ●  the operator's input (echoed back)
//   ⏵  a tool/module dispatch ("running …")
//   ✓  success
//   ✗  failure
//   ◆  agent message (LLM)
//   …  streaming/in-flight
//   ▸  a finding
//   ·  ambient/log
function logLine(kind, ts, segs, width = W120, key) {
  const glyphMap = {
    in:    [' ● ', 'c-accent'],
    run:   [' ⏵ ', 'c-primary'],
    ok:    [' ✓ ', 'c-success'],
    err:   [' ✗ ', 'c-danger'],
    agent: [' ◆ ', 'c-accent'],
    flow:  [' … ', 'c-muted'],
    find:  [' ▸ ', 'c-warn'],
    log:   [' · ', 'c-subtle'],
  };
  const g = glyphMap[kind] || glyphMap.log;
  const prefix = [
    [' ', null],
    [ts, 'c-subtle'],
    [' ', null],
    g,
  ];
  return row([...prefix, ...segs], width, key);
}

// Section header inside the console — used to group output (e.g. "FINDINGS").
function sectionHeader(label, width = W120, key) {
  return row([
    [' ', null],
    [`── ${label} `, 'c-label'],
    ['─'.repeat(Math.max(0, width - 1 - 4 - label.length - 1)), 'c-subtle'],
  ], width, key);
}

// Footer trio: thin rule, status footer, keybind footer, prompt.
function footer({ stage = 'idle', findings = 0, mod = null, keybinds = [], promptModule = null }) {
  const left = ` stage ${stage} · routing direct`;
  const rightSegs = [
    ['Ctrl+C quit · ', 'c-muted'],
    ['findings ', 'c-muted'],
    [String(findings), findings > 0 ? 'c-primary' : 'c-muted'],
    [' ', null],
  ];
  const rightLen = rightSegs.reduce((n, [t]) => n + t.length, 0);
  const statusRow = row([
    [left, 'c-muted'],
    [' '.repeat(Math.max(1, W120 - left.length - rightLen)), null],
    ...rightSegs,
  ], W120, 'sf');

  // keybinds: array of [key, hint] tuples, rendered as " ── verbs ──  k1 hint   k2 hint …"
  const kbSegs = [];
  kbSegs.push([' ', null]);
  keybinds.forEach(([k, h], i) => {
    kbSegs.push([k, 'c-accent']);
    kbSegs.push([' ', null]);
    kbSegs.push([h, 'c-muted']);
    if (i !== keybinds.length - 1) kbSegs.push(['   ', null]);
  });
  const kbRow = row(kbSegs, W120, 'kb');

  const promptText = promptModule ? ` kuzushi (${promptModule})> ` : ' kuzushi> ';
  const promptRow = (
    <span className="row" key="prompt">
      <span className="c-muted">{promptText}</span>
      <span style={{background: 'var(--t-primary)', color: 'var(--term-bg)'}}>{' '}</span>
      <span>{' '.repeat(W120 - promptText.length - 1)}</span>
    </span>
  );

  return [
    ruleRow(W120, 'foot-rule'),
    statusRow,
    kbRow,
    promptRow,
  ];
}

// The terminal frame chrome (mac traffic lights + title)
function TermFrame({ title, children }) {
  return (
    <div className="term-frame" style={{height: '100%'}}>
      <div className="term-chrome">
        <div className="dot r"></div><div className="dot y"></div><div className="dot g"></div>
        <div className="title">{title}</div>
      </div>
      <div className="term">{children}</div>
    </div>
  );
}

// Export
Object.assign(window, {
  W120, padTo, row, blankRow, ruleRow,
  statusStrip, logLine, sectionHeader, footer, TermFrame,
});
