// Taint-iris-next view — newer iris generation. Pairs static graph with an
// LLM-driven path summarizer + cross-language linking.

function TaintIrisNextView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  function bar(label, done, total, status, color = 'c-success') {
    const width = 24;
    const pct = total === 0 ? 0 : done / total;
    const filled = Math.round(width * pct);
    const empty = width - filled;
    return [
      [(label + ' '.repeat(20)).slice(0, 20), 'c-primary'],
      [' [', 'c-subtle'],
      ['█'.repeat(filled), color],
      ['░'.repeat(empty), 'c-subtle'],
      ['] ', 'c-subtle'],
      [(`${done}/${total}`).padStart(7), 'c-muted'],
      ['  ', null],
      [status, color],
    ];
  }

  // Cross-language hop visualization: ts → grpc → rust
  const hop = (idx, lang, sym, where, kind) => window.row([
    T('   '),
    [`  ${idx}  `, 'c-subtle'],
    [(lang.padEnd(7)).slice(0, 7), 'c-warn'],
    [(sym + ' '.repeat(50)).slice(0, 42), 'c-primary'],
    [(where + ' '.repeat(40)).slice(0, 30), 'c-muted'],
    [kind, 'c-accent'],
  ], W, idx);

  const lines = [
    window.logLine('in',  '14:51:10', [m(' /use '), a('taint-iris-next')], W, 'l1'),
    window.logLine('in',  '14:51:18', [m(' /run '), a('hunt --crosslang ts,rust,py --llm-summary')], W, 'l2'),
    window.logLine('run', '14:51:18', [m(' taint-iris-next:hunt · 3 langs · cross-grpc enabled · model '), p('openai:gpt-4.1')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('typescript graph    ', 612, 612, 'done · 19 nodes', 'c-success')], W, 'p1'),
    window.row([T('   '), ...bar('rust graph          ', 248, 248, 'done · 14 nodes', 'c-success')], W, 'p2'),
    window.row([T('   '), ...bar('python graph        ',  88,  88, 'done ·  6 nodes', 'c-success')], W, 'p3'),
    window.row([T('   '), ...bar('grpc bridge resolve ',   7,   7, 'done',           'c-success')], W, 'p4'),
    window.row([T('   '), ...bar('llm summarize       ',   4,   4, 'done',           'c-success')], W, 'p5'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('CROSS-LANG PATH · 6 hops · sev CRITICAL', W, 'sec-pp'),
    hop('1', 'ts',    "POST /reviews body.text                 (source)",        "apps/web/server.ts:201",      "source"),
    hop('2', 'ts',    "reviews.persist → reviews.proto Review  (encode)",        "apps/web/reviews.ts:62",      "encode"),
    hop('3', 'grpc',  "ReviewService.Persist                   (rpc)",           "proto/reviews.proto:14",       "wire"),
    hop('4', 'rust',  "review_service::persist_review          (decode)",        "apps/api/reviews.rs:34",       "decode"),
    hop('5', 'rust',  "memory_recall::index_for_concierge      (propagator)",    "apps/api/concierge.rs:88",     "propagate"),
    hop('6', 'rust',  "openai_client::chat(system=...)         (sink)",          "apps/api/concierge.rs:142",    "sink"),
    window.blankRow(W, 'b3'),

    window.sectionHeader('LLM SUMMARY', W, 'sec-l'),
    window.row([T('   '), m('a review body persisted by the TS web tier is later embedded into the Rust concierge')], W, 'sm1'),
    window.row([T('   '), m('agent\u2019s system prompt — the language boundary hides this from single-lang SAST.')], W, 'sm2'),
    window.row([T('   '), m('mitigation: tag '), p('Review.body'), m(' as untrusted in '), p('reviews.proto'), m('; reject in decode.')], W, 'sm3'),
    window.blankRow(W, 'b4'),

    window.logLine('find', '14:51:51', [
      [' ', null], ['F-0015', 'c-accent'], ['  ', null],
      [('CRITICAL').padEnd(9), 'c-sev-critical'],
      [('cross-lang prompt-injection · ts → grpc → rust').padEnd(45), 'c-primary'],
      ['  reviews.proto:14 · concierge.rs:142', 'c-muted'],
    ], W, 'fnd'),
    window.logLine('log', '14:51:51', [m(' graph: '), p('.kuzushi/runs/.../iris-next.json'), m(' · '), p('38 KB')], W, 'l-end'),
    window.logLine('agent', '14:51:51', [
      m(' iris-next found 1 path iris-classic could not — the grpc boundary masked the TS→Rust hop. promote with '), a('/promote F-0015'),
    ], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · taint-iris-next · cross-lang hunt">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'taint-iris-next', cost: '$0.34' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'taint-iris-next (done) · F-0015 critical', findings: 1,
        promptModule: 'taint-iris-next',
        keybinds: [
          ['/promote', 'F-0015'], ['/show', 'graph | summary'],
          ['/use', 'patch F-0015'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.TaintIrisNextView = TaintIrisNextView;
