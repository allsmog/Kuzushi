// Patch view — DEFENSE module. Suggests a fix patch for a verified finding.
// Renders a unified diff with rationale + tests + human approval gate.

function PatchView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  // Diff line builder
  function diff(kind, text, key) {
    const pfx = kind === 'add' ? '+ ' : kind === 'del' ? '- ' : '  ';
    const cls = kind === 'add' ? 'c-success' : kind === 'del' ? 'c-danger' : 'c-muted';
    return window.row([T('     '), [pfx, cls], [text, cls]], W, key);
  }

  function fileHead(path, key) {
    return window.row([T('   '), m('── '), [path, 'c-accent'], m(' '.repeat(Math.max(1, W - 4 - 4 - path.length - 1))), m('──')], W, key);
  }

  const lines = [
    window.logLine('in',  '15:18:11', [m(' /use '), a('patch')], W, 'l1'),
    window.logLine('in',  '15:18:18', [m(' /run '), a('F-0001 --style minimal')], W, 'l2'),
    window.logLine('run', '15:18:18', [m(' patch · drafting against '), p('orders.rs:142'), m(' · model '), p('openai:gpt-4.1')], W, 'l3'),
    window.blankRow(W, 'b1'),

    window.sectionHeader('RATIONALE', W, 'sec-r'),
    window.row([T('   '), m('replace '), p('format!()'), m(' concatenation with parameterized '), p('sqlx::query!()'), m(' macro'), m('  ·  no API change')], W, 'r1'),
    window.row([T('   '), m('side-effect: closes '), a('F-0001'), m(' (sqli) and '), a('F-0014'), m(' (codeql rust/sql-injection rust:204)')], W, 'r2'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('DIFF · 1 file · +9 −4', W, 'sec-d'),
    fileHead('apps/api/orders.rs', 'fh1'),
    diff('ctx', '@@ -138,9 +138,12 @@ pub async fn fetch_order(id: &str, db: &PgPool)', 'd1'),
    diff('ctx', "    -> Result<Order, OrderError> {", 'd2'),
    diff('del', "    let q = format!(\"SELECT * FROM orders WHERE id={}\", id);", 'd3'),
    diff('del', "    let row = sqlx::query(&q)", 'd4'),
    diff('del', "        .fetch_one(db)", 'd5'),
    diff('del', "        .await?;", 'd6'),
    diff('add', "    let row = sqlx::query!(", 'd7'),
    diff('add', "        \"SELECT id, total_cents, currency, status FROM orders WHERE id = $1\",", 'd8'),
    diff('add', "        Uuid::parse_str(id).map_err(|_| OrderError::BadId)?", 'd9'),
    diff('add', "    )", 'd10'),
    diff('add', "    .fetch_one(db)", 'd11'),
    diff('add', "    .await?;", 'd12'),
    diff('ctx', "    Ok(row.into())", 'd13'),
    diff('ctx', " }", 'd14'),
    window.blankRow(W, 'b3'),

    window.sectionHeader('TESTS · added · 2', W, 'sec-t'),
    window.row([T('   '), [' ✓ ', 'c-success'], p('orders::tests::rejects_sqli_payload'), m(' · "1 OR 1=1" → BadId')], W, 't1'),
    window.row([T('   '), [' ✓ ', 'c-success'], p('orders::tests::happy_path_uuid'), m('     · valid uuid → row')], W, 't2'),
    window.blankRow(W, 'b4'),

    window.sectionHeader('GUARDRAIL', W, 'sec-g'),
    window.row([T('   '), [' ! ', 'c-warn'], m(' '), p('approval.patches = human-required'), m(' — patch is staged, NOT applied')], W, 'g1'),
    window.row([T('   '), m('   ▸ '), a('/patch apply'), m(' to write to disk · '), a('/patch reject'), m(' to discard · '), a('/patch regen --style defensive'), m(' to redraft')], W, 'g2'),
    window.blankRow(W, 'b5'),

    window.logLine('agent', '15:18:42', [m(' minimal patch keeps the public signature; codeql query '), p('rust/sql-injection'), m(' will pass on next scan.')], W, 'l-end'),
    window.logLine('log',   '15:18:42', [m(' staged at '), p('.kuzushi/runs/2026-05-06T15-18/patch.diff'), m(' · '), p('signed=false')], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · patch · F-0001 · staged">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'patch', cost: '$0.11' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'patch · staged (human-required)', findings: 1,
        promptModule: 'patch',
        keybinds: [
          ['/patch', 'apply | reject | regen'], ['/show', 'diff | tests'],
          ['/use', 'verify F-0001 --rerun'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.PatchView = PatchView;
