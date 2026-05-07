// patch:apply hit a conflict on disk.

function PatchConflictView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function code(text, c, n) {
    const numCell = (String(n) + ' '.repeat(5)).slice(0, 4);
    return window.row([T(' '), [numCell, 'c-subtle'], [' ', null], [text, c]], W, 'c'+n);
  }

  const lines = [
    window.logLine('in','14:33:08',[m(' a')], W, 'l1'),
    window.logLine('run','14:33:08',[m(' apply F-0002 staged hunks · 1 file · '), p('apps/web/agents/concierge.ts')], W, 'l2'),
    window.logLine('err','14:33:08',[
      m(' '), [' apply refused ', 'c-danger'], m(' · '), p('apps/web/agents/concierge.ts'),
      m(' has changed on disk since the patch was drafted'),
    ], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('CONFLICT · concierge.ts', W, 's1'),
    window.row([T('   '), m('drafted against  '), p('SHA d41a2cc · 14:30:08')], W, 'k1'),
    window.row([T('   '), m('on disk now      '), p('SHA 7be19f0 · 14:32:51 · author '), p('avi.k'), m(' · '), p('+12 / -3')], W, 'k2'),
    window.row([T('   '), m('overlap          '), p('lines 84..92'), m(' touched by both')], W, 'k3'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('OURS (drafted)', W, 's2'),
    code('-  const sys = `${BASE_SYSPROMPT}\\n\\nReview context: ${review.body}`;', 'c-danger', 85),
    code('+  const sys = BASE_SYSPROMPT;', 'c-success', 85),
    code('+  const userTurn = sanitiseInline(review.body);', 'c-success', 86),
    window.blankRow(W, 'b3'),
    window.sectionHeader('THEIRS (on disk)', W, 's3'),
    code('-  const sys = `${BASE_SYSPROMPT}\\n\\nReview context: ${review.body}`;', 'c-danger', 85),
    code('+  const sys = `${BASE_SYSPROMPT}\\n\\nReview: ${redactPII(review.body)}`;', 'c-success', 85),
    code('   // upstream avi.k 14:32 · adds redactPII()', 'c-muted', 86),
    window.blankRow(W, 'b4'),
    window.sectionHeader('OPTIONS', W, 's4'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('three-way'),
      m('   re-run patcher with HEAD as base · merges sanitiseInline + redactPII')], W, 'o1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('rebase'),
      m('      drop ours · re-draft from upstream HEAD')], W, 'o2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('force apply'),
      m(' overwrite · '), [' destructive ', 'c-danger'], m(' loses redactPII')], W, 'o3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), a('open editor'),
      m('  resolve manually with .ours / .theirs / .merged on disk')], W, 'o4'),
    window.row([T('   '), [' 5 ', 'c-accent'], m('  '), a('cancel'),
      m('      finding stays open, nothing written')], W, 'o5'),
    window.blankRow(W, 'b5'),
    window.logLine('agent','14:33:09',[
      m(' the two changes are independent · suggest '), a('three-way'),
      m(' so you keep '), p('redactPII'), m(' AND get the role-tagged user envelope.'),
    ], W, 'l4'),
  ];

  return (
    <window.TermFrame title="kuzushi · patch · CONFLICT">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'patch', cost: '$0.18' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'patch · CONFLICT · 1 file · 9-line overlap', findings: 38,
        promptModule: 'patch',
        keybinds: [['1','three-way'],['2','rebase'],['3','force'],['4','editor'],['5','cancel']],
      })}
    </window.TermFrame>
  );
}
window.PatchConflictView = PatchConflictView;
