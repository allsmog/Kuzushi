// empty states — no findings, no runs, no kb, no targets.

function EmptyStatesView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function panel(title, glyph, lines, ctas) {
    const out = [];
    out.push(window.row([T('  '), [`── ${title} `, 'c-label'],
      ['─'.repeat(W - 4 - title.length - 4), 'c-subtle']], W, title));
    out.push(window.row([T('       '), [glyph, 'c-subtle']], W, title+'g'));
    for (const l of lines) out.push(window.row([T('       '), [l, 'c-muted']], W, title+l));
    out.push(window.blankRow(W, title+'sp'));
    for (const c of ctas) {
      out.push(window.row([T('       '), [' ▸ ', 'c-warn'], [c[0], 'c-accent'], ['  ', null], [c[1], 'c-muted']], W, title+c[0]));
    }
    out.push(window.blankRow(W, title+'end'));
    return out;
  }

  const lines = [
    window.logLine('in','14:40:01',[m(' /findings')], W, 'l1'),
    window.blankRow(W, 'b1'),
    ...panel('FINDINGS · empty', '∅  no findings yet', [
      'kuzushi keeps the ledger in .kuzushi/v2/findings.sqlite3.',
      'nothing has been promoted on this workspace.',
    ], [
      ['/map',  'open only the Map phase planning picker'],
      ['/scan', 'open only the Scan phase planning picker'],
      ['/full', 'guided Map → Scan · hand off to Review or Report'],
    ]),
    ...panel('RUNS · empty', '∅  no runs persisted', [
      'every dispatch writes a run dir under .kuzushi/runs/<id>/.',
      'this workspace has not run a module yet.',
    ], [
      ['/map',  'start with the Map phase planning picker'],
      ['/scan', 'start only the Scan phase planning picker'],
      ['/full', 'run the guided workflow · full . explicitly selects cwd'],
    ]),
    ...panel('KB · empty', '∅  no advisories indexed', [
      'kuzushi can pull KEV / NVD / CISA advisories into ~/.kuzushi/v2/kb.',
      'nothing pulled yet.',
    ], [
      ['/kb pull kev',           '↓ 21 MB · refreshes daily'],
      ['/kb pull nvd --since 30d','last 30d only · 4 MB'],
      ['/kb pull cwe',            'taxonomy · static · 1 MB'],
    ]),
    ...panel('TARGETS · empty', '∅  no workspaces', [
      'launch from a folder you want to audit.',
      'workspaces hold context, runs, findings, and config — never the source.',
    ], [
      ['kuzushi ~/work/acme-checkout',     'init in-place'],
      ['/workspace init ./apps/web',        'narrower scope'],
      ['/load gh:acme/checkout',            'clone via shallow git'],
    ]),
  ];

  return (
    <window.TermFrame title="kuzushi · empty states">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'empty-states · 0 findings · 0 runs · 0 kb · 0 workspaces', findings: 0,
        keybinds: [['/map','Map planner'],['/scan','Scan planner'],['/full','full workflow'],['?','help']],
      })}
    </window.TermFrame>
  );
}
window.EmptyStatesView = EmptyStatesView;
