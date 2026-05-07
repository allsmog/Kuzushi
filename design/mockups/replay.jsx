// /replay r-2108 — step through a recorded run frame-by-frame.

function ReplayView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function step(focused, idx, when, kind, msg) {
    const kMap = { call: 'c-accent', tool: 'c-success', llm: 'c-label', err: 'c-danger', note: 'c-muted' };
    const iCell = (idx + ' '.repeat(6)).slice(0, 6);
    const wCell = (when + ' '.repeat(10)).slice(0, 10);
    const kCell = (kind + ' '.repeat(8)).slice(0, 6);
    if (focused) {
      const text = ' ' + iCell + wCell + kCell + (msg + ' '.repeat(80)).slice(0, 92) + ' ';
      return <span className="row" key={idx}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return [
      ['    ', null],
      [iCell, 'c-subtle'],
      [wCell, 'c-muted'],
      [kCell, kMap[kind] || 'c-muted'],
      [msg, 'c-primary'],
    ];
  }
  const wrap = (v, k) => Array.isArray(v) ? window.row(v, W, k) : v;

  const lines = [
    window.logLine('in','15:08:00',[m(' /replay '), a('r-2108'), m(' '), a('--at 17')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('run     '), p('r-2108'), m('  ·  '), p('carlini-threat-hunt:run'), m('  ·  '), p('h=2'), m('  ·  '),
      p('12m04s'), m('  ·  '), [' ok ', 'c-success']], W, 'h1'),
    window.row([T('  '), m('frames  '), p('1 / 38 / 64'), m('   ('), m('begin / cursor / end'), m(')   ·   '),
      m('artifacts '), p('.kuzushi/runs/r-2108/')], W, 'h2'),
    window.row([T('  '), m('scrub   '), [' ◄ ', 'c-accent'], [' ', null], ['█'.repeat(22), 'c-accent'], ['░'.repeat(40), 'c-subtle'], [' ', null], [' ► ', 'c-accent'],
      m('   38/64 ·  '), m(' .58 ')], W, 'h3'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('FRAMES · ±5 around cursor', W, 's1'),
    wrap(step(false,'33', '13:38:11', 'tool', 'kb:fetch a-04 → 8 chunks'), 'a'),
    wrap(step(false,'34', '13:38:14', 'llm',  'gpt-4.1 · 1812 tok in / 184 tok out · $0.04'), 'b'),
    wrap(step(false,'35', '13:38:17', 'call', 'agent → tool: workspace:grep("review.body")'), 'c'),
    wrap(step(false,'36', '13:38:18', 'tool', '3 hits · concierge.ts:88, refund-bot.ts:127, dispute.ts:14'), 'd'),
    wrap(step(false,'37', '13:38:21', 'llm',  'plan: focus refund-bot — pricing field unsanitised'), 'e'),
    wrap(step(true ,'38', '13:38:24', 'call', 'agent → tool: sandbox:run curl … (poc draft)'), 'f'),
    wrap(step(false,'39', '13:38:26', 'tool', 'http 200 · agent leak · pricing override $-9999.99'), 'g'),
    wrap(step(false,'40', '13:38:27', 'note', 'finding promoted: F-0012 critical · prompt-injection refund-bot'), 'h'),
    wrap(step(false,'41', '13:38:31', 'llm',  'next: variant lift on payment fields'), 'i'),
    wrap(step(false,'42', '13:38:34', 'tool', 'variant:lift cve=CVE-2024-1234'), 'j'),
    wrap(step(false,'43', '13:38:39', 'tool', '0 matches · variant query unique to curl'), 'k'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('FRAME 38 · INPUT', W, 's2'),
    window.row([T('   '), p('sandbox:run'), m(' { '), p('"cmd"'), m(': '), p('"curl"'), m(', '), p('"args"'), m(': '),
      p('["-X","POST","https://refund.acme/q","-d","@poc.json"]'), m(', '), p('"net"'), m(': '), p('"isolated"'), m(' }')], W, 'd1'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','15:08:00',[
      m(' '), a('n / p'), m(' next/prev frame  ·  '), a('f <n>'), m(' jump  ·  '), a('e'), m(' export from cursor  ·  '), a('/back'),
    ], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /replay r-2108">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'replay', module: 'replay', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'replay r-2108 · frame 38/64', findings: 38,
        promptModule: 'replay',
        keybinds: [['n/p','step'],['f <n>','jump'],['e','export'],['/trace','dump']],
      })}
    </window.TermFrame>
  );
}
window.ReplayView = ReplayView;
