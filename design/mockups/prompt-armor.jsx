// Prompt-armor view — LLM-application defense module. Scans agents,
// analyzes prompt structure, simulates attacks, exports a defense report.

function PromptArmorView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const d = (t) => [t, 'c-danger'];
  const T = (t) => [t, null];

  function step(label, status, summary) {
    const c = status === 'done' ? 'c-success' : status === 'flagged' ? 'c-danger' : 'c-warn';
    return [
      [' ', null],
      [(label + ' '.repeat(28)).slice(0, 26), 'c-accent'],
      [(status + '   ').slice(0, 8), c],
      [summary, 'c-primary'],
    ];
  }

  function attack(name, sev, outcome, where) {
    const sevMap = { critical: 'c-sev-critical', high: 'c-sev-high', medium: 'c-sev-medium' };
    return [
      [' ', null],
      [(name + ' '.repeat(38)).slice(0, 34), 'c-primary'],
      [(sev.toUpperCase() + ' '.repeat(10)).slice(0, 9), sevMap[sev]],
      [(outcome + ' '.repeat(20)).slice(0, 16), outcome === 'BREACH' ? 'c-danger' : outcome === 'BLOCKED' ? 'c-success' : 'c-warn'],
      [where, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in',  '15:24:08', [m(' /use '), a('prompt-armor')], W, 'l1'),
    window.logLine('ok',  '15:24:08', [m(' plugin '), p('prompt-armor/std@2.1'), m(' from '), p('$KUZUSHI_PROMPT_ARMOR_PLUGIN'), m(' · 14 attacks · 6 analyzers')], W, 'l2'),
    window.logLine('in',  '15:24:14', [m(' /run '), a('scan && analyze && attack --suite default')], W, 'l3'),
    window.blankRow(W, 'b1'),

    window.sectionHeader('PIPELINE', W, 'sec-pp'),
    window.row(step('scan',     'done',    'discovered '), W, 'pp1a'),
    window.row([T('   '), [' ', null], [' '.repeat(28), null], m('   '), p('3 agents'), m(' · '), p('concierge'), m(', '), p('refund-bot'), m(', '), p('billing-bot')], W, 'pp1b'),
    window.row(step('analyze',  'flagged', 'system-prompt structure issues in 2 agents'), W, 'pp2'),
    window.row(step('attack',   'done',    '14 attacks · 4 BREACH · 2 PARTIAL · 8 BLOCKED'), W, 'pp3'),
    window.row(step('diff',     'done',    'baseline drift since last run: +3 BREACH, -1 PARTIAL'), W, 'pp4'),
    window.row(step('report',   'done',    'wrote .prompt-armor/2026-05-06.html'), W, 'pp5'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('ANALYZE FINDINGS', W, 'sec-an'),
    window.row([T('   '), [' ! ', 'c-warn'], p('concierge'), m('  · system prompt mixes ')], W, 'an1a'),
    window.row([T('   '), m('              '), w('user-controlled review text'), m(' before instructions block')], W, 'an1b'),
    window.row([T('   '), [' ! ', 'c-warn'], p('refund-bot'), m(' · ticket subject concatenated into role:system without delimiters')], W, 'an2'),
    window.row([T('   '), [' ✓ ', 'c-success'], p('billing-bot'), m('· structured prompt · all user data inside tagged blocks')], W, 'an3'),
    window.blankRow(W, 'b3'),

    window.sectionHeader('ATTACK MATRIX · 14 attacks', W, 'sec-am'),
    window.row(attack('A1: direct override "ignore previous"',           'medium',   'BLOCKED', 'sys-prompt sentinel held'), W, 'am1'),
    window.row(attack('A2: review-body splice (conf-12-words)',           'critical', 'BREACH',  'concierge · review.body'), W, 'am2'),
    window.row(attack('A3: ticket-subject splice',                         'critical', 'BREACH',  'refund-bot · ticket.subject'), W, 'am3'),
    window.row(attack('A4: tool-result poisoning (order.notes)',           'high',     'BREACH',  'concierge · second-order'), W, 'am4'),
    window.row(attack('A5: image alt-text smuggling',                       'medium',   'PARTIAL', 'concierge · alt parsed'), W, 'am5'),
    window.row(attack('A6: unicode bidi flip',                              'medium',   'BLOCKED', 'normalize() in pre-pass'), W, 'am6'),
    window.row(attack('A7: tool-arg jailbreak via JSON.stringify',          'high',     'BREACH',  'refund-bot · stringify path'), W, 'am7'),
    window.row(attack('A8: long-context distractor (50KB)',                 'medium',   'BLOCKED', 'truncated at 32KB'), W, 'am8'),
    window.row([T('   '), m('   … 6 more · '), a('/show attacks all')], W, 'am-more'),
    window.blankRow(W, 'b4'),

    window.logLine('agent', '15:24:48', [m(' four BREACH paths share a fix: wrap untrusted strings in '), p('<user_data>…</user_data>'), m(' tags + reject role-tokens.')], W, 'l-end'),
    window.logLine('log', '15:24:48', [m(' report at '), p('.prompt-armor/2026-05-06.html'), m(' · '), p('318 KB'), m(' · '), a('/prompt-armor diff'), m(' for run-over-run')], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · prompt-armor · scan + analyze + attack">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'prompt-armor', cost: '$0.61' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'prompt-armor · 4 BREACH · 2 PARTIAL', findings: 4,
        promptModule: 'prompt-armor',
        keybinds: [
          ['/show', 'attacks all | report'], ['/prompt-armor', 'diff | report'],
          ['/use', 'patch'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.PromptArmorView = PromptArmorView;
