// /history — transcript utilities. Searchable command history + /clear, /load.

function HistoryView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];

  function entry(focused, n, when, mod, cmd) {
    const nCell  = (n + ' '.repeat(6)).slice(0, 6);
    const wCell  = (when + ' '.repeat(10)).slice(0, 10);
    const mCell  = (mod + ' '.repeat(16)).slice(0, 14);
    const cCell  = cmd;
    if (focused) {
      const text = ' ' + nCell + wCell + mCell + cCell + ' ';
      return <span className="row" key={n}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return [
      ['    ', null],
      [nCell, 'c-subtle'],
      [wCell, 'c-muted'],
      [mCell, 'c-label'],
      [cCell, 'c-primary'],
    ];
  }

  const wrap = (v, k) => Array.isArray(v) ? window.row(v, W, k) : v;

  const search = window.row([
    [' ', null],
    ['(reverse-i-search)`', 'c-muted'],
    ['hunt', 'c-warn'],
    [`': `, 'c-muted'],
    ['/run carlini-threat-hunt:run', 'c-primary'],
    [' ', null],
    ['{"h":2}', 'c-accent'],
  ], W, 'sr');

  const heads = window.row([
    ['    ', null],
    [('#' + ' '.repeat(6)).slice(0, 6), 'c-label'],
    [('time' + ' '.repeat(10)).slice(0, 10), 'c-label'],
    [('module' + ' '.repeat(14)).slice(0, 14), 'c-label'],
    ['command', 'c-label'],
  ], W, 'h');

  const rows = [
    wrap(entry(false,'1042','13:12:08','—',          '/auth'), 'a'),
    wrap(entry(false,'1043','13:12:18','—',          '/model openai:gpt-4.1'), 'b'),
    wrap(entry(false,'1044','13:14:02','context',    '/run build'), 'c'),
    wrap(entry(false,'1045','13:18:41','threat-model','/threats build'), 'd'),
    wrap(entry(false,'1046','13:21:18','threat-model','/threats apply'), 'e'),
    wrap(entry(false,'1047','13:24:00','sast',       '/scan'), 'f'),
    wrap(entry(false,'1048','13:27:42','sast',       '/task block taint-iris'), 'g'),
    wrap(entry(true ,'1049','13:31:55','carlini',    '/run carlini-threat-hunt:run {"h":2}'), 'h'),
    wrap(entry(false,'1050','13:42:11','findings',   '/findings --severity high+ --status open,verified'), 'i'),
    wrap(entry(false,'1051','13:42:18','findings',   '/open F-0002'), 'j'),
    wrap(entry(false,'1052','13:51:08','verify',     '/use verify F-0002'), 'k'),
    wrap(entry(false,'1053','14:01:12','patch',      '/use patch F-0002 --staged'), 'l'),
    wrap(entry(false,'1054','14:08:00','—',          '/cost'), 'm'),
    wrap(entry(false,'1055','14:11:34','agentic-sast','/options agentic-sast:scan'), 'n'),
    wrap(entry(false,'1056','14:14:02','—',          '/kb'), 'o'),
    wrap(entry(false,'1057','14:31:55','sast',       '/scan'), 'p'),
  ];

  const lines = [
    window.logLine('in','14:50:00', [m(' /history')], W, 'l1'),
    window.logLine('flow','14:50:00', [m(' (Ctrl+R is searching live · '), a('hunt'), m(' matches 4 entries)')], W, 'l1b'),
    window.blankRow(W, 'b1'),
    search,
    window.blankRow(W, 'b2'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'r'),
    ...rows,
    window.blankRow(W, 'b3'),
    window.sectionHeader('UTILITIES', W, 'su'),
    window.row([['   ', null], a('/clear'), m('       wipe scrollback (history is preserved)')], W, 'u1'),
    window.row([['   ', null], a('/load <spec>'), m(' replay a saved run · gh:owner/repo@sha · file:path · run:r-…')], W, 'u2'),
    window.row([['   ', null], a('/story'), m('        narrate the session as a triage memo')], W, 'u3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /history">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$1.42' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/history · 1057 entries · search active', findings: 38,
        keybinds: [['Ctrl+R','search'],['enter','re-run'],['e','edit then run'],['/clear','wipe scroll']],
      })}
    </window.TermFrame>
  );
}

window.HistoryView = HistoryView;
