// /use ndiff CVE-2026-2941 · variant hunt in flight

function NdiffRunningView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function bar(label, done, total, status, color) {
    const w = 24;
    const pct = total === 0 ? 0 : done / total;
    const filled = Math.round(w * pct);
    return [
      [(label + ' '.repeat(22)).slice(0, 20), 'c-primary'],
      [' [', 'c-subtle'],
      ['█'.repeat(filled), color || 'c-success'],
      ['░'.repeat(w - filled), 'c-subtle'],
      ['] ', 'c-subtle'],
      [(`${done}/${total}`).padStart(11), 'c-muted'],
      ['  ', null],
      [status, color || 'c-success'],
    ];
  }

  const lines = [
    window.logLine('in','15:24:01',[m(' /use ndiff '), a('CVE-2026-2941')], W, 'l1'),
    window.logLine('run','15:24:01',[m(' lifting upstream patch '), p('postgres@a8210cc..b91c0e0'),
      m(' · 4 hunks · 41 files (deps included)')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('lift class shape    ',   4,   4, 'auth-bypass via PAM short-circuit',     'c-success')], W, 'p1'),
    window.row([T('   '), ...bar('build query         ',   1,   1, 'taint shape · auth + condition·invert','c-success')], W, 'p2'),
    window.row([T('   '), ...bar('match dependents    ',  18,  41, 'walking workspace deps · postgres-rs','c-warn')], W, 'p3'),
    window.row([T('   '), ...bar('candidate variants  ',   3,  12, 'tracing dataflows…',                  'c-warn')], W, 'p4'),
    window.row([T('   '), ...bar('verify (sandbox)    ',   0,   3, 'queued · awaiting sandbox spawn',      'c-muted')], W, 'p5'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('UPSTREAM PATCH · key hunks', W, 's1'),
    window.row([T('   '), [' h1 ', 'c-warn'], m('  '), p('src/backend/auth/pam.c'),
      m('       short-circuit if PAM_AUTH_ERR but session still set')], W, 'h1'),
    window.row([T('   '), [' h2 ', 'c-warn'], m('  '), p('src/backend/auth/auth.c'),
      m('       remove fallthrough on retry')], W, 'h2'),
    window.row([T('   '), [' h3 ', 'c-warn'], m('  '), p('src/backend/auth/RFC.h'),
      m('        rename PAM_REPROMPT to PAM_AUTH_REPROMPT')], W, 'h3'),
    window.row([T('   '), [' h4 ', 'c-warn'], m('  '), p('test/regress/pam_test.c'),
      m('     two new regression cases')], W, 'h4'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('CANDIDATE VARIANTS · 3 / 12', W, 's2'),
    window.row([T('   '), [' V1 ', 'c-accent'], m('  '), p('libs/payments/src/auth.rs:84..118'),
      m(' · '), [' high ', 'c-sev-high'], m('  shape match: '), p('0.91'),
      m('  · variants of '), p('h1'), m(' "short-circuit ok"')], W, 'v1'),
    window.row([T('   '), [' V2 ', 'c-accent'], m('  '), p('apps/api/sessions/issue.rs:201..240'),
      m(' · '), [' med ', 'c-sev-medium'], m('  shape match: '), p('0.74'),
      m(' · variant of '), p('h2'), m(' "fallthrough on retry"')], W, 'v2'),
    window.row([T('   '), [' V3 ', 'c-accent'], m('  '), p('jobs/worker/auth.py:14..52'),
      m(' · '), [' med ', 'c-sev-medium'], m('  shape match: '), p('0.68'),
      m(' · cross-lang variant of '), p('h1'), m(' (py)')], W, 'v3'),
    window.row([T('   '), [' … ', 'c-subtle'], m('  9 candidates pending · '),
      p('agentic-sast'), m(' tracing each · '), [' verify on accept ', 'c-warn']], W, 'vMore'),
    window.blankRow(W, 'b4'),
    window.logLine('agent','15:24:38',[
      m(' '), [' early call ', 'c-warn'], m(' '), p('V1'), m(' is the same shape as '), p('h1'),
      m(' down to the same comment ("safe to ignore — set later"). high confidence.'),
    ], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · ndiff · CVE-2026-2941 · variant hunt">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'ndiff', cost: '$0.18' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'ndiff · CVE-2026-2941 · 3/12 candidates · 0/3 verified', findings: 38,
        promptModule: 'ndiff',
        keybinds: [['/pause','halt'],['j/k','candidate'],['v','verify'],['?','agent']],
      })}
    </window.TermFrame>
  );
}
window.NdiffRunningView = NdiffRunningView;
