// Workspace view — current workspace state. Active runs, recent runs, KB
// attachments, target & branch, persisted findings rollup, export hooks.

function WorkspaceView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  function kvl(key, val, note) {
    return [
      [' ', null],
      [(key + ' '.repeat(20)).slice(0, 18), 'c-muted'],
      [(val + ' '.repeat(50)).slice(0, 48), 'c-primary'],
      [note ? note : '', 'c-muted'],
    ];
  }

  function runRow(id, mod, when, status, findings) {
    const c = status === 'done' ? 'c-success' : status === 'running' ? 'c-warn' : status === 'failed' ? 'c-danger' : 'c-muted';
    return [
      [' ', null],
      [(id + ' '.repeat(24)).slice(0, 22), 'c-accent'],
      [(mod + ' '.repeat(20)).slice(0, 18), 'c-primary'],
      [(when + ' '.repeat(14)).slice(0, 12), 'c-muted'],
      [(status + '   ').slice(0, 9), c],
      [String(findings).padStart(4) + ' findings', 'c-muted'],
    ];
  }

  function rollupBar(sev, n, total) {
    const cmap = { critical: 'c-sev-critical', high: 'c-sev-high', medium: 'c-sev-medium', low: 'c-sev-low' };
    const w = 28;
    const filled = Math.max(1, Math.round(w * n / total));
    return [
      [' ', null],
      [(sev.toUpperCase() + ' '.repeat(10)).slice(0, 9), cmap[sev]],
      [' [', 'c-subtle'],
      ['█'.repeat(filled), cmap[sev]],
      ['░'.repeat(w - filled), 'c-subtle'],
      ['] ', 'c-subtle'],
      [String(n).padStart(3), 'c-primary'],
      ['/', 'c-subtle'],
      [String(total), 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in',  '15:45:08', [m(' /workspace')], W, 'l1'),
    window.logLine('run', '15:45:08', [m(' workspace:status · '), p('~/work/acme-checkout'), m(' · branch '), p('main@7c9aa11')], W, 'l2'),
    window.blankRow(W, 'b1'),

    window.sectionHeader('TARGET', W, 'sec-t'),
    window.row(kvl('path',          '~/work/acme-checkout',                                'git · main@7c9aa11 · clean'), W, 't1'),
    window.row(kvl('snapshot',      '.kuzushi/context-snapshot.json',                      '184 KB · built 41m ago'), W, 't2'),
    window.row(kvl('threat-model',  '.kuzushi/threat-model.json',                          'v3 · awaiting v4 review'), W, 't3'),
    window.row(kvl('findings db',   '.kuzushi/v2/findings.sqlite3',                        '38 findings · 4.2 MB'), W, 't4'),
    window.row(kvl('artifact KB',   '.kuzushi/v2/artifact-kb.sqlite3',                     '88 chunks · 12 docs'), W, 't5'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('FINDINGS ROLLUP · 38 persisted', W, 'sec-r'),
    window.row(rollupBar('critical', 4, 38),  W, 'r1'),
    window.row(rollupBar('high',     11, 38), W, 'r2'),
    window.row(rollupBar('medium',   14, 38), W, 'r3'),
    window.row(rollupBar('low',       9, 38), W, 'r4'),
    window.blankRow(W, 'b3'),

    window.sectionHeader('RUNS · last 6', W, 'sec-runs'),
    window.row(runRow('run_2026-05-06T15-38', 'iac-scan',          '7m ago',    'done',    20), W, 'rn1'),
    window.row(runRow('run_2026-05-06T15-24', 'prompt-armor',      '21m ago',   'done',     4), W, 'rn2'),
    window.row(runRow('run_2026-05-06T15-18', 'patch',             '27m ago',   'staged',   1), W, 'rn3'),
    window.row(runRow('run_2026-05-06T15-11', 'verify',            '34m ago',   'done',     1), W, 'rn4'),
    window.row(runRow('run_2026-05-06T14-55', 'agentic-sast',      '50m ago',   'done',     2), W, 'rn5'),
    window.row(runRow('run_2026-05-06T14-31', 'sast',              '1h 14m',    'done',    11), W, 'rn6'),
    window.row([T('   '), m('   ▸ '), a('/show runs all'), m(' · '), a('/replay run_2026-05-06T15-11'), m(' to step through')], W, 'rn-cta'),
    window.blankRow(W, 'b4'),

    window.sectionHeader('ATTACHMENTS · 4', W, 'sec-att'),
    window.row([T('   '), [' [pdf]   ', 'c-danger'], p('docs/pentest-2025-q4.pdf'),       m('   2.1 MB · attached 3d ago')], W, 'at1'),
    window.row([T('   '), [' [url]   ', 'c-accent'], p('owasp.org/Top10/'),               m('   metadata-only · 14d ago')], W, 'at2'),
    window.row([T('   '), [' [md]    ', 'c-warn'],   p('docs/threat-stories.md'),        m('   38 KB · attached 1d ago')], W, 'at3'),
    window.row([T('   '), [' [json]  ', 'c-warn'],   p('.kuzushi/randori/v1.json'),       m('   88 KB · auto')], W, 'at4'),
    window.blankRow(W, 'b5'),

    window.logLine('log', '15:45:11', [m(' export: '), a('/workspace export findings .kuzushi/findings.json'), m(' · sbom: '), a('/dep sbom export')], W, 'l-end'),
  ];

  return (
    <window.TermFrame title="kuzushi · workspace · /workspace status">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'workspace', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'workspace · 38 findings · 1 patch staged', findings: 38,
        promptModule: 'workspace',
        keybinds: [
          ['/show', 'runs all'], ['/replay', '<runId>'],
          ['/workspace', 'export findings'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.WorkspaceView = WorkspaceView;
