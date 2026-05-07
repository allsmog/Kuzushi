// Verify view — DEFENSE module. Reproduces a finding by building a runnable
// PoC trace, then asserts exploitability. Single-finding focus.

function VerifyView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  const toolUse = (name, args, result, key) =>
    window.row([
      [' ', null], ['   ', null],
      ['⏵ ', 'c-subtle'],
      [name, 'c-accent'],
      ['(', 'c-subtle'], [args, 'c-muted'], [') ', 'c-subtle'],
      ['→ ', 'c-subtle'],
      [result, 'c-primary'],
    ], W, key);

  function step(num, label, status, detail) {
    const sc = status === 'PASS' ? 'c-success' : status === 'FAIL' ? 'c-danger' : 'c-warn';
    return [
      [' ', null],
      [`  ${num}  `, 'c-subtle'],
      [(label + ' '.repeat(34)).slice(0, 32), 'c-accent'],
      [(status + '   ').slice(0, 6), sc],
      [detail, 'c-primary'],
    ];
  }

  const lines = [
    window.logLine('in',  '15:11:02', [m(' /use '), a('verify')], W, 'l1'),
    window.logLine('in',  '15:11:09', [m(' /run '), a('F-0001 --rerun')], W, 'l2'),
    window.logLine('run', '15:11:09', [m(' verify · '), a('F-0001'), m(' · '), p('sql injection via order_id concatenation')], W, 'l3'),
    window.blankRow(W, 'b1'),

    window.sectionHeader('REPRO PLAN · 5 steps', W, 'sec-plan'),
    window.row(step('I',   'isolate sink',           'PASS', 'orders.rs:142 · format!("WHERE id={}",id) → sqlx::query'), W, 's1'),
    window.row(step('II',  'reach taint source',     'PASS', 'POST /orders { order_id: "1 OR 1=1" } accepted'), W, 's2'),
    window.row(step('III', 'craft payload',          'PASS', "1' UNION SELECT password FROM users--"), W, 's3'),
    window.row(step('IV',  'execute against fixture','PASS', 'docker fixture · 200 OK · 14 rows leaked'), W, 's4'),
    window.row(step('V',   'assert impact',          'PASS', 'pwd hashes returned · CIA-C breach confirmed'), W, 's5'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('TOOL TRACE', W, 'sec-tt'),
    toolUse('read_file',  'apps/api/orders.rs:120-160',                            '40 lines',                    'tu1'),
    toolUse('docker',     'compose up acme-api-fixture',                           'ready in 3.4s',               'tu2'),
    toolUse('http',       "POST /orders order_id=\"1' UNION SELECT password…\"",   '200 OK · 14 rows',            'tu3'),
    toolUse('assert',     'rows.len() > 0 && contains("$argon2")',                  'TRUE',                        'tu4'),
    window.blankRow(W, 'b3'),

    window.sectionHeader('VERDICT · EXPLOITABLE', W, 'sec-v'),
    window.row([T('   '), [' ✓ ', 'c-success'], p('reachable'), m('  · '), p('source POST /orders.body.order_id'), m(' → '), p('sink orders.rs:142')], W, 'v1'),
    window.row([T('   '), [' ✓ ', 'c-success'], p('exploitable'), m(' · 14 rows leaked from users table · CIA-C')], W, 'v2'),
    window.row([T('   '), [' ✓ ', 'c-success'], p('reproducible'), m(' · 3/3 fresh containers'), m(' · '), p('seed=acme-fixture@v1.4')], W, 'v3'),
    window.row([T('   '), m('   PoC: '), p('.kuzushi/runs/2026-05-06T15-11/poc.sh'), m('  ·  trace: '), p('verify.jsonl')], W, 'v4'),
    window.blankRow(W, 'b4'),

    window.logLine('agent', '15:11:48', [
      m(' verified · finding promoted to '), w('verified'), m(' · SLA breach in '), w('56h'), m('. patch with '), a('/use patch F-0001'), m('.'),
    ], W, 'l-end'),
    window.logLine('log',   '15:11:48', [m(' wrote '), p('.kuzushi/v2/findings.sqlite3'), m(' · '), p('verdict=true_positive')], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · verify · F-0001 · sql injection">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'verify', cost: '$0.08' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'verify (done) · F-0001 EXPLOITABLE', findings: 1,
        promptModule: 'verify',
        keybinds: [
          ['/use', 'patch F-0001'], ['/show', 'trace | poc'],
          ['/findings', 'next open'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.VerifyView = VerifyView;
