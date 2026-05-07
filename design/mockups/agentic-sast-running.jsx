// Agentic-SAST — IN PROGRESS. Mid variant hunt: one finding emitted, second
// in flight. Tool-use list is still scrolling.

function AgenticSastInProgressView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  const cursor = (
    <span style={{ background: 'var(--t-primary)', color: 'var(--term-bg)' }}>{' '}</span>
  );

  const toolUse = (name, args, result, key) =>
    window.row([
      [' ', null], ['   ', null],
      ['⏵ ', 'c-subtle'],
      [name, 'c-accent'],
      ['(', 'c-subtle'], [args, 'c-muted'], [') ', 'c-subtle'],
      ['→ ', 'c-subtle'],
      [result, 'c-primary'],
    ], W, key);

  // tool-use line, in flight (no result yet)
  const toolUseRunning = (name, args, key) => (
    <span className="row" key={key}>
      <span>{'    '}</span>
      <span className="c-subtle">{'⏵ '}</span>
      <span className="c-accent">{name}</span>
      <span className="c-subtle">{'('}</span>
      <span className="c-muted">{args}</span>
      <span className="c-subtle">{') '}</span>
      <span className="c-warn">{'⠿ '}</span>
      <span className="c-muted">{'running'}</span>
      {cursor}
      <span>{' '.repeat(Math.max(0, W - 4 - 2 - name.length - 2 - args.length - 2 - 2 - 7 - 1))}</span>
    </span>
  );

  const lines = [
    window.logLine('in', '14:55:18', [m(' /use '), a('agentic-sast')], W, 'l1'),
    window.logLine('in', '14:55:25', [m(' /run '), a('--seed F-0002 --hunt variants')], W, 'l2'),
    window.logLine('run', '14:55:25', [m(' agentic-sast:scan · seed '), a('F-0002'), m(' · model '), p('openai:gpt-4.1')], W, 'l3'),
    window.blankRow(W, 'b1'),

    window.logLine('agent', '14:55:27', [
      [' seed: concierge agent reads user-controlled review text into its system prompt.', 'c-primary'],
    ], W, 'a1'),
    window.logLine('flow', '14:55:27', [
      [' looking for variants \u2014 other places untrusted text \u2192 model call', 'c-muted'],
    ], W, 'a1b'),
    toolUse('grep', '"messages.push", "system:", "buildPrompt"', '14 hits across 6 files', 'tu1'),
    toolUse('read_file', 'apps/web/agents/concierge.ts:60-110', '50 lines', 'tu2'),
    toolUse('read_file', 'apps/web/agents/refund-bot.ts:1-160', '160 lines', 'tu3'),
    window.logLine('agent', '14:55:34', [
      [' ', null], ['refund-bot.ts:120-138', 'c-warn'],
      [' splices ticket subject \u2014 same shape as F-0002.', 'c-primary'],
    ], W, 'a2'),
    toolUse('taint-step', 'sources=[ticket.subject], sinks=[openai.chat.create]', 'reachable in 3 hops', 'tu4'),
    window.logLine('find', '14:55:38', [
      [' ', null], ['F-0012', 'c-accent'], ['  ', null],
      [('CRITICAL').padEnd(9), 'c-sev-critical'],
      [('prompt-injection in refund-bot').padEnd(45), 'c-primary'],
      ['  refund-bot.ts:127', 'c-muted'],
    ], W, 'fnd1'),
    window.blankRow(W, 'b2'),

    window.logLine('agent', '14:55:42', [
      [' continuing the hunt \u2014 looking for ', 'c-primary'],
      ['indirect', 'c-warn'],
      [' splices: untrusted text \u2192 tool arg \u2192 model.', 'c-primary'],
    ], W, 'a3'),
    toolUse('grep', '"tools:", "function:", "execute("', '22 hits across 9 files', 'tu5'),
    toolUse('read_file', 'apps/web/agents/concierge.ts:200-260', '60 lines', 'tu6'),
    // Currently-running tool call
    toolUseRunning('taint-step', 'sources=[order.notes], sinks=[concierge.system_msg]', 'tu7'),
    // Streaming agent thought
    <span className="row" key="stream">
      <span>{' '}</span>
      <span className="c-subtle">14:55:48</span>
      <span>{' '}</span>
      <span className="c-accent">{' ◆ '}</span>
      <span className="c-primary">{'order.notes is operator-editable from a Slack bot — second-order'}</span>
      {cursor}
      <span>{' '.repeat(W - 1 - 8 - 1 - 3 - 64 - 1)}</span>
    </span>,
  ];

  const customStrip = window.row([
    [' ', null],
    ['KUZUSHI', 'c-heading'], ['  ', null],
    ['target ', 'c-muted'], ['~/work/acme-checkout', 'c-primary'], ['  ', null],
    ['module ', 'c-muted'], ['agentic-sast', 'c-accent'], ['  ', null],
    ['stage ', 'c-muted'], ['⠷ tracing 0:23', 'c-warn'], ['  ', null],
    ['cost ', 'c-muted'], ['$0.34', 'c-primary'],
  ], W, 'strip');

  return (
    <window.TermFrame title="kuzushi · agentic-sast · variant hunt in flight">
      {customStrip}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'agentic-sast · 1 finding · taint-step in flight', findings: 12,
        promptModule: 'agentic-sast',
        keybinds: [
          ['Ctrl+C', 'cancel'], ['/pause', 'halt'],
          ['/show', 'live trace'], ['/skip', 'this hop'],
        ],
      })}
    </window.TermFrame>
  );
}

window.AgenticSastInProgressView = AgenticSastInProgressView;
