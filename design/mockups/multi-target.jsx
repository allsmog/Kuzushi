// multi-target · /workspace init  multi-repo monorepo

function MultiTargetView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function tgt(focused, mark, name, root, lang, files, slcc) {
    const mCell = (mark + ' '.repeat(8)).slice(0, 6);
    const nCell = (name + ' '.repeat(22)).slice(0, 18);
    const rCell = (root + ' '.repeat(36)).slice(0, 32);
    const lCell = (lang + ' '.repeat(16)).slice(0, 14);
    const fCell = (files + ' '.repeat(10)).slice(0, 8);
    const sCell = slcc;
    if (focused) {
      const text = ' ' + mCell + nCell + rCell + lCell + fCell + sCell;
      return <span className="row" key={name}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [mCell, mark.includes('★') ? 'c-warn' : 'c-success'],
      [nCell, 'c-primary'],
      [rCell, 'c-muted'],
      [lCell, 'c-accent'],
      [fCell, 'c-muted'],
      [sCell, 'c-muted'],
    ], W, name);
  }

  const heads = window.row([
    ['    ', null],
    [('mark' + ' '.repeat(6)).slice(0, 6), 'c-label'],
    [('target' + ' '.repeat(18)).slice(0, 18), 'c-label'],
    [('root' + ' '.repeat(32)).slice(0, 32), 'c-label'],
    [('language' + ' '.repeat(14)).slice(0, 14), 'c-label'],
    [('files' + ' '.repeat(8)).slice(0, 8), 'c-label'],
    ['SLOC', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','15:10:01',[m(' /workspace init '), a('~/work/acme-monorepo --multi')], W, 'l1'),
    window.logLine('run','15:10:01',[m(' detected '), p('5'), m(' targets · '),
      p('apps/'), m(' + '), p('libs/'), m(' + '), p('infra/'), m(' + '), p('jobs/'), m(' + '), p('vendor/')], W, 'l2'),
    window.blankRow(W, 'b1'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'r'),
    tgt(false, '★ primary',  'apps-web',         'apps/web',                       'ts',                   '482',  '142,180'),
    tgt(true,  '✓',          'apps-api',         'apps/api',                       'rust',                 '128',   '38,420'),
    tgt(false, '✓',          'libs-payments',    'libs/payments',                  'rust',                 '34',     '8,120'),
    tgt(false, '✓',          'jobs-worker',      'jobs/worker',                    'py',                   '22',     '3,860'),
    tgt(false, '✓',          'infra-k8s',        'infra/k8s',                      'yaml',                 '47',       '1,180'),
    tgt(false, '·',          'vendor-redis',     'vendor/redis-rs (read-only)',     'rust',                 '0',         '—'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('CROSS-LANG TAINT · candidate edges', W, 's2'),
    window.row([T('   '), [' edge ', 'c-warn'], m('  '), p('apps-web'), m('  →  '), p('jobs-worker'),
      m('  via '), p('redis://kuzushi-q'), m('  ·  '), m('agentic-sast taint-iris-next will follow')], W, 'e1'),
    window.row([T('   '), [' edge ', 'c-warn'], m('  '), p('apps-api'), m('  →  '), p('libs-payments'),
      m('  via '), p('extern crate'), m('  ·  '), m('static linking · followed by default')], W, 'e2'),
    window.row([T('   '), [' edge ', 'c-warn'], m('  '), p('apps-web'), m('  →  '), p('apps-api'),
      m('  via '), p('http://api'),    m('  ·  '), m('schema-shared types in libs/contracts')], W, 'e3'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('PROPOSED MODES', W, 's3'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('--mode unified'),
      m('   one workspace, all 5 targets, single findings ledger · '), p('recommended')], W, 'm1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('--mode federated'),
      m('  one workspace per target, cross-target context bus · slower · richer cross-lang taint')], W, 'm2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('--mode primary apps-web'),
      m(' just apps-web; treat the rest as opaque')], W, 'm3'),
    window.blankRow(W, 'b4'),
    window.row([T('   '), [' i ', 'c-accent'], m('  '), p('vendor/redis-rs'),
      m(' will be read-only · taint follows in but never out · no patches will be drafted there')], W, 'in1'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','15:10:01',[m(' '), a('y'), m(' confirm '),
      a('--mode unified'), m(' · '), a('e'), m(' edit · '),
      a('1..5'), m(' to toggle a target inactive')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /workspace init --multi · 5 targets">
      {window.statusStrip({ target: '~/work/acme-monorepo', ctx: 'building', module: 'workspace', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'multi-target · 5 targets · 3 cross-lang edges', findings: 0,
        promptModule: 'workspace',
        keybinds: [['j/k','row'],['1..5','toggle'],['y','confirm'],['e','edit']],
      })}
    </window.TermFrame>
  );
}
window.MultiTargetView = MultiTargetView;
