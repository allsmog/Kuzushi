// design system · final reference page

function DesignSystemView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function head(label) {
    return window.row([
      [' ', null], [`── ${label} `, 'c-label'],
      ['─'.repeat(Math.max(0, W - 1 - 4 - label.length - 1)), 'c-subtle'],
    ], W, 'h-' + label);
  }

  const lines = [
    head('TYPOGRAPHY'),
    window.row([T('   '), m('family   '), p('JetBrains Mono'),
      m('  weights '), p('400 / 500 / 700'),  m('  ligatures '), p('off')], W, 'ty1'),
    window.row([T('   '), m('size     '), p('12.5px'),
      m('  line-height '), p('1.28'),  m('  grid '), p('120 cols × 16px rows')], W, 'ty2'),
    window.row([T('   '), m('preview  '), p('the quick brown fox jumps over the lazy dog 0123456789')], W, 'ty3'),
    window.row([T('   '), m('         '), p('THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG !@#$%^&*()_+')], W, 'ty4'),
    window.blankRow(W, 'b1'),
    head('COLOR · 8-role theme'),
    window.row([T('   '), [' heading      ', 'c-heading'], m('  #ffffff'),
      m('   '), [' label    ', 'c-label'],   m('  #a6cdff')], W, 'c1'),
    window.row([T('   '), [' primary      ', 'c-primary'], m('  #cfd6e0'),
      m('   '), [' accent   ', 'c-accent'],  m('  #7fb8ff')], W, 'c2'),
    window.row([T('   '), [' muted        ', 'c-muted'],   m('  #7d8794'),
      m('   '), [' subtle   ', 'c-subtle'],  m('  #3d4654')], W, 'c3'),
    window.row([T('   '), [' success      ', 'c-success'], m('  #57c479'),
      m('   '), [' warn     ', 'c-warn'],    m('  #e2c14a')], W, 'c4'),
    window.row([T('   '), [' danger       ', 'c-danger'],  m('  #e25c5c'),
      m('   '), [' selection', 'c-sel'],     m('  #7fb8ff on bg')], W, 'c5'),
    window.blankRow(W, 'b2'),
    head('SEVERITY'),
    window.row([T('   '), [' CRITICAL ', 'c-sev-critical'],
      m('  '), [' HIGH    ', 'c-sev-high'],
      m('  '), [' MEDIUM  ', 'c-sev-medium'],
      m('  '), [' LOW     ', 'c-sev-low']], W, 'sv1'),
    window.blankRow(W, 'b3'),
    head('GLYPHS · console line kinds'),
    window.row([T('   '), [' ● ', 'c-accent'], m('  in       (operator input echo)'),
      T('     '), [' ⏵ ', 'c-primary'], m('  run      (tool / module dispatch)')], W, 'g1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  ok       (success)'),
      T('             '), [' ✗ ', 'c-danger'],  m('  err      (failure / refused)')], W, 'g2'),
    window.row([T('   '), [' ◆ ', 'c-accent'], m('  agent    (LLM message)'),
      T('             '), [' … ', 'c-muted'],   m('  flow     (streaming / in-flight)')], W, 'g3'),
    window.row([T('   '), [' ▸ ', 'c-warn'],   m('  find     (a finding / red flag)'),
      T('       '), [' · ', 'c-subtle'], m('  log      (ambient · low signal)')], W, 'g4'),
    window.blankRow(W, 'b4'),
    head('CONSOLE LINE · timestamp + glyph + body'),
    window.logLine('in',    '14:31:55', [m(' /scan')], W, 'cl1'),
    window.logLine('run',   '14:31:55', [m(' sast:scan · tasks '), a('semgrep, secrets'), m(' · triage on')], W, 'cl2'),
    window.logLine('agent', '14:33:42', [m(' two CRITICALs share a sink — '), a('F-0001'),
      m(' and '), a('F-0002'), m(' both end at '), [' orders.rs:142', 'c-warn']], W, 'cl3'),
    window.logLine('find',  '14:33:42', [m(' '), p('F-0012'), m(' · '),
      [' CRITICAL ', 'c-sev-critical'], m(' · '), p('refund-bot.ts:127')], W, 'cl4'),
    window.logLine('err',   '15:46:01', [m(' '), [' HARD STOP ', 'c-danger'],
      m(' · run budget reached')], W, 'cl5'),
    window.blankRow(W, 'b5'),
    head('SECTION HEADER'),
    window.sectionHeader('FINDINGS · 11 triaged · 7 pending', W, 'sh1'),
    window.blankRow(W, 'b6'),
    head('SELECTION · the j/k cursor'),
    window.row([T('  '), ['  ▌', 'c-accent'],
      [' F-0001  CRITICAL  sql injection via order_id concatenation         apps/api/orders.rs:142  ', 'c-sel']], W, 'se1'),
    window.row([T('     '), [' F-0002', 'c-accent'], m('  '), [' CRITICAL ', 'c-sev-critical'],
      m('  prompt-injection — model reads user body         '), m('apps/web/agents/concierge.ts:88')], W, 'se2'),
    window.blankRow(W, 'b7'),
    head('PROGRESS BARS'),
    window.row([T('   '),
      [('semgrep             ').padEnd(20).slice(0,20), 'c-primary'], [' [', 'c-subtle'],
      ['█'.repeat(24), 'c-success'], ['] ', 'c-subtle'],
      [' 612/612', 'c-muted'], m('  '), ['done', 'c-success']], W, 'pb1'),
    window.row([T('   '),
      [('agentic-sast        ').padEnd(20).slice(0,20), 'c-primary'], [' [', 'c-subtle'],
      ['█'.repeat(17), 'c-warn'], ['░'.repeat(7), 'c-subtle'], ['] ', 'c-subtle'],
      [' 87/120', 'c-muted'], m('  '), ['tracing dataflows…', 'c-warn']], W, 'pb2'),
    window.row([T('   '),
      [('budget              ').padEnd(20).slice(0,20), 'c-primary'], [' [', 'c-subtle'],
      ['█'.repeat(24), 'c-danger'], ['] ', 'c-subtle'],
      [' $2.50/$2.50', 'c-muted'], m('  '), ['hard stop', 'c-danger']], W, 'pb3'),
    window.blankRow(W, 'b8'),
    head('SEVERITY CHIPS · status pills'),
    window.row([T('   '), [' open ', 'c-warn'], m(' '), [' triaging ', 'c-warn'], m(' '),
      [' verified ', 'c-success'], m(' '), [' patched ', 'c-success'], m(' '),
      [' fixed ', 'c-success'], m(' '), [' refused ', 'c-danger'], m(' '),
      [' WONTFIX ', 'c-muted']], W, 'ch1'),
    window.blankRow(W, 'b9'),
    head('BANNER · red-flag · refused · hard-stop'),
    window.row([T('   '), ['╔══ RED FLAG ', 'c-danger'],
      ['═'.repeat(W - 4 - 12 - 1), 'c-danger'], ['╗', 'c-danger']], W, 'bn1'),
    window.row([T('   '), ['║ ', 'c-danger'],
      [' refund-bot accepts review.body in sysmsg AND has refund tool · canonical $-loss shape '.padEnd(W - 8, ' '), 'c-primary'],
      [' ║', 'c-danger']], W, 'bn2'),
    window.row([T('   '), ['╚', 'c-danger'], ['═'.repeat(W - 6), 'c-danger'], ['╝', 'c-danger']], W, 'bn3'),
    window.blankRow(W, 'b10'),
    head('STATUS STRIP · top of every screen'),
    window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', model: 'openai:gpt-4.1', module: 'sast', cost: '$0.41' }),
    window.blankRow(W, 'b11'),
    head('FOOTER · stage line · keybind line · prompt'),
    window.ruleRow(W, 'fr'),
    window.row([
      [' stage sast:scan · agentic 73% · triage 61%', 'c-muted'],
      [' '.repeat(W - 60 - 16), null],
      ['Ctrl+C quit · ', 'c-muted'], ['findings ', 'c-muted'], ['11', 'c-primary'], [' ', null],
    ], W, 'st'),
    window.row([
      [' ', null],
      ['/findings', 'c-accent'], [' browse   ', 'c-muted'],
      ['/open',    'c-accent'], [' F-0001   ', 'c-muted'],
      ['/use',     'c-accent'], [' verify   ', 'c-muted'],
      ['/pause',   'c-accent'], [' halt scan', 'c-muted'],
    ], W, 'kb'),
    <span className="row" key="pr">
      <span className="c-muted">{' kuzushi (sast)> '}</span>
      <span style={{background: 'var(--t-primary)', color: 'var(--term-bg)'}}>{' '}</span>
    </span>,
    window.blankRow(W, 'b12'),
    head('GRID · everything inside a 120 × 40 frame'),
    window.row([T('   '),
      m('cols  '), p('120'),  m('     line  '), p('16px'),  m('     frame '), p('120 × 40 ≈ 1080 × 640'),
      m('     padding '), p('12 / 14'),  m('     radius '), p('8px frame · 6px inner')], W, 'gr1'),
    window.row([T('   '),
      m('chrome '), p('macos traffic-lights'),  m(' · '),
      m('title '), p('module · view · cols'),  m(' · '),
      m('bg    '), p('#0b0d10'),
    ], W, 'gr2'),
    window.blankRow(W, 'b13'),
    head('PRINCIPLES'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), p('growing console'),
      m('  · all output appends downward · the page is your transcript')], W, 'pr1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), p('cite or it didn\'t happen'),
      m('  · every claim names a file:line, a finding id, or a run id')], W, 'pr2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), p('refusal is a feature'),
      m('  · refusals get banners, gate stacks, and a clear path to widen')], W, 'pr3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), p('one accent color'),
      m('  · #7fb8ff is reserved for next-action callouts and selection — never decoration')], W, 'pr4'),
    window.row([T('   '), [' 5 ', 'c-accent'], m('  '), p('keybinds always visible'),
      m('  · the bottom strip is the contract for what works on this view')], W, 'pr5'),
    window.row([T('   '), [' 6 ', 'c-accent'], m('  '), p('cost on screen always'),
      m('  · status strip and footer agree on what this turn just spent')], W, 'pr6'),
    window.row([T('   '), [' 7 ', 'c-accent'], m('  '), p('no decorative motion'),
      m('  · only progress bars + scrubbers move; everything else is static')], W, 'pr7'),
    window.row([T('   '), [' 8 ', 'c-accent'], m('  '), p('metasploit muscle memory'),
      m('  · /use, /set, /run, /show, /options · matches the operator\'s hands')], W, 'pr8'),
  ];

  return (
    <window.TermFrame title="kuzushi · design system">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'design-system', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'design-system · reference', findings: 38,
        promptModule: 'design-system',
        keybinds: [['j/k','row'],['/help','keybinds'],['/?','this page']],
      })}
    </window.TermFrame>
  );
}
window.DesignSystemView = DesignSystemView;
