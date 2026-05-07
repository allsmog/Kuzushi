// /tasks — current task selection for the sast umbrella.

function TasksView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function task(focused, allow, id, mode, time, blurb) {
    const allowGlyph = allow === 'allow' ? [' ✓ ', 'c-success']
                     : allow === 'block' ? [' ✗ ', 'c-danger']
                     : [' · ', 'c-subtle'];
    const idCell = (id + ' '.repeat(28)).slice(0, 26);
    const mCell  = (mode + ' '.repeat(10)).slice(0, 8);
    const tCell  = (time + ' '.repeat(10)).slice(0, 8);
    if (focused) {
      const text = '   ' + idCell + mCell + tCell + ' ' + (blurb + ' '.repeat(60)).slice(0, 60) + ' ';
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return [
      ['  ', null], allowGlyph, ['  ', null],
      [idCell, 'c-accent'],
      [mCell, 'c-muted'],
      [tCell, 'c-muted'],
      [blurb, 'c-primary'],
    ];
  }
  const wrap = (v, k) => Array.isArray(v) ? window.row(v, W, k) : v;

  const lines = [
    window.logLine('in','15:03:00',[m(' /tasks')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('module '), p('sast'), m('  ·  task mode '), [' auto ', 'c-accent'],
               m('  ·  scope '), p('workspace'), m('  ·  triage '), [' on ', 'c-success')], W, 'h1'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('SELECTION · 6 visible · 4 active', W, 's1'),
    wrap(task(false,'allow','semgrep',           'auto', '2.4s',   'pattern-based SAST · always cheap'), 'a'),
    wrap(task(false,'allow','secret-scan',       'auto', '0.8s',   'high-precision regex set'), 'b'),
    wrap(task(true ,'allow','agentic-sast',      'auto', '~3min',  'LLM dataflow + variant hunt — pricey but high-signal'), 'c'),
    wrap(task(false,'allow','triage (post-scan)','auto', '~30s',   'classifies raw hits, dedupes against existing findings'), 'd'),
    wrap(task(false,'block','codeql',            'manual','—',     'requires codeql binary (missing) — refusing'), 'e'),
    wrap(task(false,'block','taint-iris',        'manual','~6min', 'experimental cross-lang taint — opt-in only'), 'f'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('CHANGES THIS SESSION', W, 's2'),
    window.row([T('  '), [' ✗ ', 'c-danger'], T('  '), p('block taint-iris'), m('   13:27 by '), p('avi.k'), m('   reason: experimental, want to A/B vs agentic-sast')], W, 'c1'),
    window.row([T('  '), [' ✗ ', 'c-danger'], T('  '), p('block codeql   '), m('   13:27 (auto)   '), m(' reason: codeql binary not on $PATH')], W, 'c2'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','15:03:00',[
      m(' override per task with '), a('/task allow <id>'), m(' · '), a('/task block <id>'),
      m(' · reset with '), a('/task reset'), m(' · switch mode with '), a('/task mode manual'),
    ], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /tasks">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'sast', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/tasks · 4 active · 2 blocked', findings: 38,
        promptModule: 'sast',
        keybinds: [['j/k','row'],['a','allow'],['b','block'],['/task','reset|mode']],
      })}
    </window.TermFrame>
  );
}
window.TasksView = TasksView;
