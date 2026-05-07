// /diff workspace · vs main and vs snapshot

function DiffWorkspaceView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function f(focused, st, file, hunks, by) {
    const stMap = { M:[' M ', 'c-warn'], A:[' A ', 'c-success'], D:[' D ', 'c-danger'], R:[' R ', 'c-accent'] };
    const fCell = (file + ' '.repeat(60)).slice(0, 56);
    const hCell = (hunks + ' '.repeat(14)).slice(0, 12);
    const bCell = by;
    if (focused) {
      const text = ' ' + ' M ' + ' ' + fCell + hCell + bCell;
      return <span className="row" key={file}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['   ', null],
      stMap[st], [' ', null],
      [fCell, 'c-primary'],
      [hCell, 'c-muted'],
      [bCell, 'c-accent'],
    ], W, file);
  }

  const lines = [
    window.logLine('in','15:52:01',[m(' /diff workspace '), a('--vs main'),
      m('  ·  '), a('--vs snap snap-tag1')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('left  '), p('main @ 6e8f81b'),
      m(' (3 days ago)'),  m('   right  '), p('working tree'),
      m('   ·  '), m('also '), p('snap-tag1'), m(' (14:08 today)')], W, 'h0'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('CHANGES vs main · 7 files · +148 -42', W, 's1'),
    window.row([
      ['   ', null],
      [('st' + ' '.repeat(2)).slice(0, 2), 'c-label'],
      [(' file' + ' '.repeat(56)).slice(0, 57), 'c-label'],
      [('hunks' + ' '.repeat(12)).slice(0, 12), 'c-label'],
      ['by', 'c-label'],
    ], W, 'h'),
    window.row([['   ', null], ['─'.repeat(W - 3), 'c-subtle']], W, 'r'),
    f(true,  'M', 'apps/web/agents/concierge.ts',           '3 (+22 -8)',  'patcher (kuzushi)'),
    f(false, 'M', 'apps/web/agents/concierge.test.ts',     '1 (+18 -0)',  'patcher (kuzushi)'),
    f(false, 'M', '.kuzushi/threat-model.json',             '4 (+88 -22)', 'planner (kuzushi)'),
    f(false, 'A', '.kuzushi/runs/r-2113/findings/F-0012.json','1 (+14 -0)', 'attacker (kuzushi)'),
    f(false, 'A', '.kuzushi/runs/r-2117/findings/F-0027.json','1 (+8 -0)',   'attacker (kuzushi)'),
    f(false, 'M', 'package-lock.json',                       '1 (+2 -2)',   'operator'),
    f(false, 'M', '.env.example',                            '1 (+0 -1)',   'patcher (kuzushi)'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('PROVENANCE · who-changed-what · this is the audit value of /diff', W, 's2'),
    window.row([T('   '), [' ▸ ', 'c-warn'], p('5 of 7'),
      m(' files were changed by kuzushi actors · '),
      p('2 of 7'), m(' by you (operator)')], W, 'pr1'),
    window.row([T('   '), [' ▸ ', 'c-warn'], p('every kuzushi-touched file'),
      m(' carries an audit-log row at the moment of write')], W, 'pr2'),
    window.row([T('   '), [' ▸ ', 'c-warn'], p('snap-2117'),
      m(' captured pre-write originals · '),
      a('/rollback snap-2117'),  m(' restores concierge.ts side-by-side')], W, 'pr3'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('SELECTED · concierge.ts · vs main', W, 's3'),
    window.row([T('   '), m('   '), m('@@ -86,8 +86,22 @@   class ConciergeBot extends BaseBot {')], W, 'h1'),
    window.row([T('   '), [' - ', 'c-danger'], p('     const sys = `${this.basePrompt}\\n${review.body}`;')], W, 'h2'),
    window.row([T('   '), [' + ', 'c-success'], p('     const safeBody = redactSensitive(review.body);')], W, 'h3'),
    window.row([T('   '), [' + ', 'c-success'], p('     const sys = this.basePrompt; // body goes in user role')], W, 'h4'),
    window.row([T('   '), [' + ', 'c-success'], p('     const messages = [')], W, 'h5'),
    window.row([T('   '), [' + ', 'c-success'], p('       { role: "system", content: sys },')], W, 'h6'),
    window.row([T('   '), [' + ', 'c-success'], p('       { role: "user",   content: `<review>${safeBody}</review>` },')], W, 'h7'),
    window.row([T('   '), [' + ', 'c-success'], p('     ];')], W, 'h8'),
    window.blankRow(W, 'b5'),
    window.sectionHeader('vs snap-tag1 (manual baseline · 14:08)', W, 's4'),
    window.row([T('   '), m('   '), p('14 files'),  m(' · '),
      p('+228 -82'), m(' · '), p('all kuzushi actors'),
      m(' · everything since you took the manual snapshot'),
      m(' · '), a('/diff workspace --vs snap snap-tag1 --files-only')], W, 'sn1'),
    window.blankRow(W, 'b6'),
    window.logLine('flow','15:52:14',[m(' '), a('j/k'), m(' file · '),
      a('enter'), m(' open inline · '),
      a('e'), m(' edit in $EDITOR · '),
      a('s'), m(' stage all kuzushi-touched · '),
      a('S'), m(' stage selected file · '),
      a('/diff --by attacker'), m(' filter')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /diff workspace · vs main + snap">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'diff', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'diff · 7 files · 5 by kuzushi · 2 by operator', findings: 38,
        promptModule: 'diff',
        keybinds: [['j/k','file'],['enter','open'],['s','stage all'],['e','editor']],
      })}
    </window.TermFrame>
  );
}
window.DiffWorkspaceView = DiffWorkspaceView;
