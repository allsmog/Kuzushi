// /show runs — list runs from .kuzushi/runs/

function ShowRunsView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];

  function r(focused, id, when, mod, dur, status, blurb) {
    const sMap = { ok: 'c-success', err: 'c-danger', running: 'c-warn', paused: 'c-accent' };
    const idCell = (id + ' '.repeat(14)).slice(0, 12);
    const wCell  = (when + ' '.repeat(12)).slice(0, 12);
    const mCell  = (mod + ' '.repeat(22)).slice(0, 22);
    const dCell  = (dur + ' '.repeat(8)).slice(0, 8);
    const stCell = (status + ' '.repeat(10)).slice(0, 9);
    if (focused) {
      const text = ' ' + idCell + wCell + mCell + dCell + stCell + (blurb + ' '.repeat(60)).slice(0, 50) + ' ';
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return [
      ['    ', null],
      [idCell, 'c-accent'],
      [wCell, 'c-muted'],
      [mCell, 'c-label'],
      [dCell, 'c-muted'],
      [stCell, sMap[status]],
      [blurb, 'c-primary'],
    ];
  }
  const wrap = (v, k) => Array.isArray(v) ? window.row(v, W, k) : v;

  const heads = window.row([
    ['    ', null],
    [('runId' + ' '.repeat(12)).slice(0, 12), 'c-label'],
    [('time' + ' '.repeat(12)).slice(0, 12), 'c-label'],
    [('module:tool' + ' '.repeat(22)).slice(0, 22), 'c-label'],
    [('dur' + ' '.repeat(8)).slice(0, 8), 'c-label'],
    [('status' + ' '.repeat(9)).slice(0, 9), 'c-label'],
    ['summary', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','15:06:00',[m(' /show runs')], W, 'l1'),
    window.blankRow(W, 'b1'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'rule'),
    wrap(r(false,'r-2104',     '13:14:02', 'context:build',          '4.1s',   'ok',     '12 slices · 942 files'), 'a'),
    wrap(r(false,'r-2105',     '13:18:41', 'threat-model:build',     '38s',    'ok',     'STRIDE · 8 issues · v3 → v4 patch'), 'b'),
    wrap(r(false,'r-2106',     '13:21:18', 'threat-model:apply',     '0.4s',   'ok',     'committed v4'), 'c'),
    wrap(r(false,'r-2107',     '13:24:00', 'sast:scan',              '6m12s',  'ok',     '11 promoted · 7 dedupes'), 'd'),
    wrap(r(true ,'r-2108',     '13:31:55', 'carlini-threat-hunt:run','12m04s', 'ok',     'h=2 · F-0012 · prompt-injection refund-bot'), 'e'),
    wrap(r(false,'r-2109',     '13:42:11', 'findings:list',          '0.1s',   'ok',     'severity high+ status open,verified'), 'f'),
    wrap(r(false,'r-2110',     '13:51:08', 'verify:run',             '14s',    'ok',     'F-0002 reproduced · poc-h2.txt'), 'g'),
    wrap(r(false,'r-2111',     '14:01:12', 'patch:run',              '52s',    'ok',     'F-0002 staged patch · 3 files'), 'h'),
    wrap(r(false,'r-2112',     '14:11:34', 'agentic-sast:scan',      '—',      'paused', 'paused at 73% · budget guardrail'), 'i'),
    wrap(r(false,'r-2113',     '14:31:55', 'sast:scan',              '—',      'running','task agentic-sast 73% · triage 61%'), 'j'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('r-2108 · DETAIL', W, 'sd'),
    window.row([['   ', null], m('artifacts   '), p('.kuzushi/runs/r-2108/'), m(' · '), p('14 files'), m(' · '), p('1.2 MB')], W, 'd1'),
    window.row([['   ', null], m('budget      '), p('$1.94'), m(' / '), p('$2.50'), m('  ·  cited '), p('a-04, a-08')], W, 'd2'),
    window.row([['   ', null], m('next        '), a('/replay r-2108'), m('  ·  '), a('/trace r-2108'), m('  ·  '), a('/show runs r-2108 --tree')], W, 'd3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /show runs">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$1.42' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/show runs · 10 in window', findings: 38,
        keybinds: [['j/k','row'],['enter','/replay'],['t','/trace'],['/show runs --since','filter']],
      })}
    </window.TermFrame>
  );
}
window.ShowRunsView = ShowRunsView;
