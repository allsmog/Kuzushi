// Agentic-SAST view — LLM-driven dataflow + variant hunt. Shows live agent
// reasoning interleaved with tool dispatches (read_file, grep, taint-step).

function AgenticSastView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const d = (t) => [t, 'c-danger'];
  const T = (t) => [t, null];

  // Tool-use line (claude-code style "⏵ tool(args) → result")
  const toolUse = (name, args, result, key) =>
    window.row([
      [' ', null], ['   ', null],
      ['⏵ ', 'c-subtle'],
      [name, 'c-accent'],
      ['(', 'c-subtle'], [args, 'c-muted'], [') ', 'c-subtle'],
      ['→ ', 'c-subtle'],
      [result, 'c-primary'],
    ], W, key);

  const lines = [
    window.logLine('in', '14:55:18', [m(' /use '), a('agentic-sast')], W, 'l1'),
    window.logLine('in', '14:55:25', [m(' /run '), a('--seed F-0002 --hunt variants')], W, 'l2'),
    window.logLine('run', '14:55:25', [m(' agentic-sast:scan · seed '), a('F-0002'), m(' · model '), p('openai:gpt-4.1')], W, 'l3'),
    window.blankRow(W, 'b1'),

    window.logLine('agent', '14:55:27', [
      [' seed: concierge agent reads user-controlled review text into its system prompt.', 'c-primary'],
    ], W, 'a1'),
    window.logLine('flow', '14:55:27', [
      [' looking for variants — other places we splice untrusted text into a model call', 'c-muted'],
    ], W, 'a1b'),
    toolUse('grep', '"messages.push", "system:", "buildPrompt"', '14 hits across 6 files', 'tu1'),
    toolUse('read_file', 'apps/web/agents/concierge.ts:60-110', '50 lines', 'tu2'),
    toolUse('read_file', 'apps/web/agents/refund-bot.ts:1-160', '160 lines', 'tu3'),
    window.logLine('agent', '14:55:34', [
      [' ', null], ['refund-bot.ts:120-138', 'c-warn'],
      [' builds the system prompt by concatenating the ticket subject — same shape as F-0002.', 'c-primary'],
    ], W, 'a2'),
    toolUse('taint-step', 'sources=[ticket.subject], sinks=[openai.chat.create]', 'reachable in 3 hops', 'tu4'),
    window.logLine('find', '14:55:38', [
      [' ', null],
      ['F-0012', 'c-accent'], ['  ', null],
      [('CRITICAL').padEnd(9), 'c-sev-critical'],
      [('prompt-injection in refund-bot').padEnd(45), 'c-primary'],
      ['  refund-bot.ts:127', 'c-muted'],
    ], W, 'fnd1'),
    window.blankRow(W, 'b2'),

    window.logLine('agent', '14:55:42', [
      [' continuing the hunt — looking for ', 'c-primary'],
      ['indirect', 'c-warn'],
      [' splices: untrusted text → tool arg → model reads later.', 'c-primary'],
    ], W, 'a3'),
    toolUse('grep', '"tools:", "function:", "execute(', '22 hits across 9 files', 'tu5'),
    toolUse('read_file', 'apps/web/agents/concierge.ts:200-260', '60 lines', 'tu6'),
    window.logLine('agent', '14:55:49', [
      [' concierge calls a ', 'c-primary'],
      ['lookup_order', 'c-warn'],
      [' tool; its result is re-fed as context.', 'c-primary'],
    ], W, 'a4'),
    window.logLine('flow', '14:55:49', [
      [' order.', 'c-muted'], ['notes', 'c-warn'], [' is operator-editable from Slack — ', 'c-muted'], ['second-order injection.', 'c-danger'],
    ], W, 'a4b'),
    toolUse('taint-step', 'sources=[order.notes], sinks=[concierge.system_msg]', 'reachable in 5 hops via tool result', 'tu7'),
    window.logLine('find', '14:55:53', [
      [' ', null],
      ['F-0013', 'c-accent'], ['  ', null],
      [('HIGH').padEnd(9), 'c-sev-high'],
      [('second-order injection · order.notes → concierge').padEnd(45), 'c-primary'],
      ['  concierge.ts:241', 'c-muted'],
    ], W, 'fnd2'),
    window.blankRow(W, 'b3'),

    window.logLine('agent', '14:55:57', [
      [' last class: places we ', 'c-primary'],
      ['stringify JSON', 'c-warn'],
      [' of user fields into one content block.', 'c-primary'],
    ], W, 'a5'),
    toolUse('grep', '"JSON.stringify", "content:"', '8 hits, 3 in agent files', 'tu8'),
    window.logLine('agent', '14:56:02', [m(' all three already escape with '), p('safeStringify'), m(' (allowlisted keys). clean.')], W, 'a6'),
    window.blankRow(W, 'b4'),

    window.logLine('ok', '14:56:03', [
      [' variant hunt closed · ', 'c-muted'],
      ['2', 'c-primary'], [' new findings · ', 'c-muted'],
      ['9', 'c-primary'], [' tool calls · ', 'c-muted'],
      ['$0.27', 'c-primary'], [' added to run cost', 'c-muted'],
    ], W, 'l-end'),
    window.logLine('log', '14:56:03', [m(' next: '), a('/use verify F-0012'), m('  ·  '), a('/use patch F-0013'), m('  ·  '), a('/show trace')], W, 'l-cta'),
  ];

  return (
    <window.TermFrame title="kuzushi · agentic-sast · seed F-0002 · variant hunt">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'agentic-sast', cost: '$0.68' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end-1')}
      {window.footer({
        stage: 'agentic-sast (done) · 9 tool calls · 2 new findings', findings: 13,
        promptModule: 'agentic-sast',
        keybinds: [
          ['/use', 'verify F-0012'], ['/use', 'patch F-0013'],
          ['/show', 'reasoning trace'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.AgenticSastView = AgenticSastView;
