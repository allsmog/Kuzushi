// Variant view — lift a single finding into a generalized pattern, then
// hunt across the codebase for matches. Two-step: lift then hunt.

function VariantView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  function variant(id, conf, where, snippet) {
    const c = conf >= 0.85 ? 'c-danger' : conf >= 0.6 ? 'c-warn' : 'c-muted';
    return [
      [' ', null],
      [(id + ' '.repeat(8)).slice(0, 7), 'c-accent'],
      [(conf.toFixed(2) + '   ').slice(0, 6), c],
      [(where + ' '.repeat(40)).slice(0, 36), 'c-muted'],
      [snippet, 'c-primary'],
    ];
  }

  const lines = [
    window.logLine('in',  '15:02:08', [m(' /use '), a('variant')], W, 'l1'),
    window.logLine('in',  '15:02:14', [m(' /run '), a('lift-pattern --from F-0001')], W, 'l2'),
    window.logLine('run', '15:02:14', [m(' variant:lift-pattern · seeded by '), a('F-0001'), m(' (sql injection · format!() concat)')], W, 'l3'),
    window.blankRow(W, 'b1'),

    window.sectionHeader('PATTERN', W, 'sec-pp'),
    window.row([T('   '), m('shape  '), p('any format!()-style string concatenation feeding a sqlx::query / pool.query call')], W, 'pp1'),
    window.row([T('   '), m('signal '), p('format!("...{}...",X) → sqlx::query(_)'), m(' or '), p('".to_string() + Y → execute(_)')], W, 'pp2'),
    window.row([T('   '), m('lang   '), p('rust')], W, 'pp3'),
    window.row([T('   '), m('depth  '), p('1 hop · same crate')], W, 'pp4'),
    window.blankRow(W, 'b2'),

    window.logLine('in',  '15:02:21', [m(' /run '), a('hunt --pattern <lifted>')], W, 'l4'),
    window.logLine('run', '15:02:21', [m(' variant:hunt · scanning '), p('248'), m(' rust files')], W, 'l5'),
    window.blankRow(W, 'b3'),

    window.sectionHeader('VARIANTS · 6 (of 8 candidates · 2 ruled out by tests)', W, 'sec-v'),
    window.row(variant('V-1', 0.94, 'apps/api/orders.rs:142',     '(seed) format!("…WHERE id={}",id)'), W, 'v1'),
    window.row(variant('V-2', 0.91, 'apps/api/admin/users.rs:88', 'format!("…WHERE email LIKE %{}%",q)'), W, 'v2'),
    window.row(variant('V-3', 0.88, 'apps/api/billing/refund.rs:54', '"DELETE FROM refunds WHERE id=".to_owned()+id'), W, 'v3'),
    window.row(variant('V-4', 0.74, 'apps/api/reports/sales.rs:117', 'format!("…GROUP BY {}",col)'), W, 'v4'),
    window.row(variant('V-5', 0.62, 'apps/api/search.rs:204',      'format!("…ORDER BY {} {}",col,dir)'), W, 'v5'),
    window.row(variant('V-6', 0.41, 'apps/api/audit/log.rs:31',    "format!(\"INSERT INTO audit({},'{}')\",k,v)"), W, 'v6'),
    window.row([T('   '), m('   ▸ '), a('/promote V-1..V-3'), m(' as new findings · '), a('/show V-2'), m(' for diff vs seed')], W, 'v-cta'),
    window.blankRow(W, 'b4'),

    window.logLine('agent', '15:02:48', [
      m(' V-2 and V-3 are real (>0.85) — V-2 has same shape exactly. promote both. V-4..V-6 need eyes.'),
    ], W, 'l-end'),
    window.logLine('log', '15:02:48', [m(' wrote '), p('.kuzushi/runs/.../variants.json'), m(' · pattern saved at '), p('.kuzushi/patterns/sqli-format.yml')], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · variant · lift-pattern from F-0001 → hunt">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'variant', cost: '$0.13' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'variant (done) · 6 candidates · 3 high-conf', findings: 3,
        promptModule: 'variant',
        keybinds: [
          ['/promote', 'V-1..V-3'], ['/show', 'V-2 | pattern'],
          ['/use', 'patch V-2'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.VariantView = VariantView;
