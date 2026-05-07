// Triage view — DEFENSE module. LLM classifies persisted raw hits into
// findings: severity, exploitability, dedupe, suppression suggestion.

function TriageView() {
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

  function verdict(alias, sev, action, reason) {
    const sevMap = { critical: 'c-sev-critical', high: 'c-sev-high', medium: 'c-sev-medium', low: 'c-sev-low' };
    const actionMap = {
      'PROMOTE':   'c-success',
      'DEDUPE':    'c-accent',
      'SUPPRESS':  'c-subtle',
      'DOWNGRADE': 'c-warn',
    };
    return [
      [' ', null],
      [(alias + ' '.repeat(8)).slice(0, 8), 'c-accent'],
      [(sev.toUpperCase() + ' '.repeat(10)).slice(0, 9), sevMap[sev]],
      [(action + ' '.repeat(11)).slice(0, 10), actionMap[action]],
      [reason, 'c-primary'],
    ];
  }

  const lines = [
    window.logLine('in', '14:34:01', [m(' /use '), a('triage')], W, 'l1'),
    window.logLine('in', '14:34:08', [m(' /run '), a('--input semgrep,codeql --since v1.0.0')], W, 'l2'),
    window.logLine('run', '14:34:08', [m(' triage · '), p('31'), m(' raw hits · model '), p('openai:gpt-4.1')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('classify            ', 31, 31, 'done · 11 promoted', 'c-success')], W, 'p1'),
    window.row([T('   '), ...bar('dedupe              ', 31, 31, 'done · 7 merged',    'c-success')], W, 'p2'),
    window.row([T('   '), ...bar('suppression-check   ', 31, 31, 'done · 4 ignored',   'c-success')], W, 'p3'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('VERDICTS · 31 hits → 11 findings · 7 dedupes · 4 suppressed', W, 'sec-v'),
    window.row(verdict('F-0001', 'critical', 'PROMOTE',   'reachable, taint reaches sqlx::query, no parameterization'), W, 'v1'),
    window.row(verdict('F-0002', 'critical', 'PROMOTE',   'concierge sysmsg eats review.body — exploitable today'), W, 'v2'),
    window.row(verdict('F-0003', 'high',     'PROMOTE',   'jwt alg=none accepted in verify path'), W, 'v3'),
    window.row(verdict('F-0004', 'high',     'PROMOTE',   'shell=True with cron payload (worker.py:213)'), W, 'v4'),
    window.row(verdict('—',      'high',     'DEDUPE',    'codeql js/sql-injection 204 == semgrep raw hit, both → F-0001'), W, 'v5'),
    window.row(verdict('—',      'medium',   'DEDUPE',    'codeql py/cmd-injection == semgrep py rule → F-0004'), W, 'v6'),
    window.row(verdict('F-0006', 'medium',   'DOWNGRADE', 'open redirect: only /login, no oauth flow → high → medium'), W, 'v7'),
    window.row(verdict('F-0008', 'medium',   'PROMOTE',   'regex compiled from request → catastrophic backtracking'), W, 'v8'),
    window.row(verdict('F-0009', 'low',      'PROMOTE',   'cors null origin · low because authn separate'), W, 'v9'),
    window.row(verdict('—',      'low',      'SUPPRESS',  'js/insecure-randomness — used for cache keys, not crypto'), W, 'v10'),
    window.row(verdict('—',      'low',      'SUPPRESS',  'py/print-debug — local-only debug script tools/'), W, 'v11'),
    window.row([T('   '), m('   … 4 more · '), a('/show triage all')], W, 'v-more'),
    window.blankRow(W, 'b3'),

    window.logLine('agent', '14:34:48', [
      m(' '), p('F-0001'), m(' & '), p('F-0002'), m(' both ship to '), w('orders.rs:142'), m(' — single patch closes both.'),
    ], W, 'l-end'),
    window.logLine('log', '14:34:48', [m(' write triaged set: '), a('/triage apply'), m('  ·  reject single: '), a('/triage reject F-0006')], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · triage · /run --input semgrep,codeql">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'triage', cost: '$0.19' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'triage (done) · 11 promoted · 4 suppressed', findings: 11,
        promptModule: 'triage',
        keybinds: [
          ['/triage', 'apply | reject'], ['/show', 'triage all'],
          ['/use', 'verify F-0001'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.TriageView = TriageView;
