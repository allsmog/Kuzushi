// /modules — list visible native modules grouped by category, with state.

function ModulesView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];

  function row(focused, id, cat, tools, last, status) {
    const sMap = { ready: 'c-success', stale: 'c-warn', refusing: 'c-danger', '—': 'c-subtle' };
    const idCell  = (id + ' '.repeat(28)).slice(0, 26);
    const cCell   = (cat + ' '.repeat(14)).slice(0, 12);
    const tCell   = (tools + ' '.repeat(10)).slice(0, 8);
    const lCell   = (last + ' '.repeat(14)).slice(0, 12);
    if (focused) {
      const text = ' ' + idCell + cCell + tCell + lCell + (status + ' '.repeat(20)).slice(0, 18) + ' ';
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return [
      ['    ', null],
      [idCell, 'c-accent'],
      [cCell, 'c-muted'],
      [tCell, 'c-muted'],
      [lCell, 'c-muted'],
      [status, sMap[status] || 'c-muted'],
    ];
  }
  const wrap = (v, k) => Array.isArray(v) ? window.row(v, W, k) : v;

  const heads = window.row([
    ['    ', null],
    [('module' + ' '.repeat(26)).slice(0, 26), 'c-label'],
    [('cat' + ' '.repeat(12)).slice(0, 12), 'c-label'],
    [('tools' + ' '.repeat(8)).slice(0, 8), 'c-label'],
    [('last run' + ' '.repeat(12)).slice(0, 12), 'c-label'],
    ['status', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','15:00:00',[m(' /modules')], W, 'l1'),
    window.blankRow(W, 'b1'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'rule'),
    wrap(row(false,'context',              'intel',     '3', '13:14',   'ready'), 'a'),
    wrap(row(false,'recon',                'intel',     '4', '12:48',   'ready'), 'b'),
    wrap(row(false,'threat-model',         'intel',     '5', '13:21',   'ready'), 'c'),
    wrap(row(false,'randori',              'intel',     '3', '13:22',   'ready'), 'd'),
    wrap(row(true ,'sast',                 'offense',   '2', '14:31',   'ready'), 'e'),
    wrap(row(false,'semgrep',              'offense',   '2', '14:31',   'ready'), 'f'),
    wrap(row(false,'codeql',               'offense',   '2', '—',       'refusing'), 'g'),
    wrap(row(false,'secret-scan',          'offense',   '1', '14:31',   'ready'), 'h'),
    wrap(row(false,'iac-scan',             'offense',   '3', '13:11',   'ready'), 'i'),
    wrap(row(false,'dep-hygiene',          'offense',   '2', '13:09',   'ready'), 'j'),
    wrap(row(false,'agentic-sast',         'offense',   '4', '14:33',   'ready'), 'k'),
    wrap(row(false,'carlini-threat-hunt',  'offense',   '3', '13:31',   'ready'), 'l'),
    wrap(row(false,'taint-iris',           'offense',   '2', '13:42',   'ready'), 'm'),
    wrap(row(false,'taint-iris-next',      'offense',   '2', '13:43',   'ready'), 'n'),
    wrap(row(false,'variant',              'offense',   '2', '13:51',   'ready'), 'o'),
    wrap(row(false,'ndiff',                'offense',   '2', '14:01',   'ready'), 'p'),
    wrap(row(false,'x-ray',                'offense',   '3', '—',       '—'), 'q'),
    wrap(row(false,'chrome-rce',           'offense',   '4', '—',       '—'), 'r'),
    wrap(row(false,'prompt-armor',         'offense',   '3', '—',       'refusing'), 's'),
    wrap(row(false,'vuln-scout',           'offense',   '2', '—',       'refusing'), 't'),
    wrap(row(false,'vendor-assessment',    'offense',   '2', '—',       '—'), 'u'),
    wrap(row(false,'triage',               'defense',   '2', '14:34',   'ready'), 'v'),
    wrap(row(false,'verify',               'defense',   '2', '13:51',   'ready'), 'w'),
    wrap(row(false,'patch',                'defense',   '2', '14:01',   'ready'), 'x'),
    wrap(row(false,'findings',             'defense',   '4', '14:38',   'ready'), 'y'),
    wrap(row(false,'config',               'governance','3', '13:12',   'ready'), 'z'),
    wrap(row(false,'shinsa',               'governance','2', '—',       'ready'), 'A'),
    wrap(row(false,'tob',                  'governance','3', '—',       'refusing'), 'B'),
    window.blankRow(W, 'b2'),
    window.logLine('agent','15:00:01',[
      m(' '), p('25 ready'), m(' · '), ['4 refusing', 'c-danger'], m(' (missing plugin/binary) · '),
      ['1 stale', 'c-warn'], m(' · run '), a('doctor'), m(' to see why'),
    ], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /modules">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/modules · 30 visible', findings: 38,
        keybinds: [['j/k','row'],['enter','/use'],['/tools','module tools'],['/options','show options']],
      })}
    </window.TermFrame>
  );
}
window.ModulesView = ModulesView;
