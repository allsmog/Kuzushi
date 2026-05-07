// Taint-iris view — directed taint analysis. Picks sources/sinks then walks
// inter-procedural dataflow paths. Renders a path tree.

function TaintIrisView() {
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

  function pathNode(depth, glyph, label, file, key) {
    return window.row([
      T('   '),
      [' '.repeat(depth * 2), null],
      [glyph + ' ', 'c-subtle'],
      [(label + ' '.repeat(60)).slice(0, 50), 'c-primary'],
      [file, 'c-muted'],
    ], W, key);
  }

  const lines = [
    window.logLine('in',  '14:48:01', [m(' /use '), a('taint-iris')], W, 'l1'),
    window.logLine('in',  '14:48:09', [m(' /run '), a('hunt --sources http-body --sinks sql,exec --depth 8')], W, 'l2'),
    window.logLine('run', '14:48:09', [m(' taint-iris:hunt · 41 sources · 29 sinks · max-depth 8')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('source enumerate    ', 41, 41, 'done',         'c-success')], W, 'p1'),
    window.row([T('   '), ...bar('sink enumerate      ', 29, 29, 'done',         'c-success')], W, 'p2'),
    window.row([T('   '), ...bar('walk graph          ', 1189, 1189, 'done · 7 reaching paths', 'c-success')], W, 'p3'),
    window.row([T('   '), ...bar('summarize           ', 7, 7, 'done',           'c-success')], W, 'p4'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('REACHING PATHS · 7 · ranked by severity', W, 'sec-pp'),
    window.row([T('   '), [' ▸ ', 'c-warn'], a('P1'), m('  CRITICAL  '), p('http-body → sqlx::query'), m('  3 hops  '), w('SQLi')], W, 'pp1'),
    pathNode(1, '├', "POST /orders body.order_id            (source)", "apps/api/orders.rs:88",   'n1-1'),
    pathNode(1, '├', "OrderReq::from_body                   (deserialize)", "apps/api/orders.rs:104", 'n1-2'),
    pathNode(1, '├', "fetch_order(id, db)                   (propagator)", "apps/api/orders.rs:120", 'n1-3'),
    pathNode(1, '└', "format!(\"…WHERE id={}\",id) → sqlx::query (sink)", "apps/api/orders.rs:142", 'n1-4'),
    window.blankRow(W, 'b3'),
    window.row([T('   '), [' ▸ ', 'c-warn'], a('P2'), m('  CRITICAL  '), p('http-body → openai.chat'), m(' 4 hops  '), w('prompt-inj')], W, 'pp2'),
    pathNode(1, '├', "POST /reviews body.text               (source)",   "apps/web/server.ts:201",                'n2-1'),
    pathNode(1, '├', "reviews.persist                       (store)",     "apps/web/reviews.ts:62",                 'n2-2'),
    pathNode(1, '├', "memory.recall(top_k=8)                (retrieval)", "lib/memory/recall.ts:118",               'n2-3'),
    pathNode(1, '└', "buildSystemPrompt → openai.chat       (sink)",      "apps/web/agents/concierge.ts:88",        'n2-4'),
    window.blankRow(W, 'b4'),
    window.row([T('   '), [' ▸ ', 'c-warn'], a('P3'), m('  HIGH      '), p('cron-payload → subprocess'), m(' 2 hops  '), w('shell-exec')], W, 'pp3'),
    pathNode(1, '├', "queue.consume(\"refunds\")            (source)",   "jobs/worker.py:184", 'n3-1'),
    pathNode(1, '└', "subprocess.run(cmd, shell=True)       (sink)",      "jobs/worker.py:213", 'n3-2'),
    window.blankRow(W, 'b5'),
    window.row([T('   '), m('   … '), a('P4..P7'), m(' · '), a('/show paths all'), m(' · '), a('/show graph P2'), m(' for SVG')], W, 'pp-more'),
    window.blankRow(W, 'b6'),

    window.logLine('agent', '14:49:11', [
      m(' '), a('P1'), m(' and '), a('P2'), m(' both terminate at sinks already covered by '), p('F-0001'), m('/'), p('F-0002'),
      m(' — promote '), a('P3'), m(' to a fresh finding.'),
    ], W, 'l-end'),
    window.logLine('log', '14:49:11', [m(' graph cached at '), p('.kuzushi/runs/.../iris.graphml'), m(' · '), p('11 KB')], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · taint-iris · hunt --sources http-body --sinks sql,exec">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'taint-iris', cost: '$0.16' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'taint-iris (done) · 7 paths · 3 critical', findings: 7,
        promptModule: 'taint-iris',
        keybinds: [
          ['/show', 'paths all | graph'], ['/promote', 'P3'],
          ['/use', 'taint-iris-next'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.TaintIrisView = TaintIrisView;
