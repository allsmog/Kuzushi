// /show runs — scan-run artifacts ledger.

function RunsView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];

  function r(focused, id, when, dur, mods, status, findings, cost) {
    const idCell      = (id + ' '.repeat(12)).slice(0, 12);
    const whenCell    = (when + ' '.repeat(20)).slice(0, 18);
    const durCell     = (dur + ' '.repeat(10)).slice(0, 10);
    const modsCell    = (mods + ' '.repeat(36)).slice(0, 34);
    const statusCell  = (status + ' '.repeat(12)).slice(0, 11);
    const fCell       = (findings + ' '.repeat(8)).slice(0, 8);
    const costCell    = cost;
    const sColor = status === 'complete' ? 'c-success'
                 : status === 'partial'  ? 'c-warn'
                 : status === 'paused'   ? 'c-warn'
                 : status === 'failed'   ? 'c-danger'
                 : 'c-subtle';
    if (focused) {
      const text = ' ' + idCell + whenCell + durCell + modsCell + statusCell + fCell + costCell + ' ';
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return [
      ['    ', null],
      [idCell, 'c-accent'],
      [whenCell, 'c-muted'],
      [durCell, 'c-muted'],
      [modsCell, 'c-primary'],
      [statusCell, sColor],
      [fCell, 'c-primary'],
      [costCell, 'c-muted'],
    ];
  }

  const wrap = (val, key) => Array.isArray(val) ? window.row(val, W, key) : val;

  const heads = window.row([
    ['    ', null],
    [('runId' + ' '.repeat(12)).slice(0, 12), 'c-label'],
    [('started' + ' '.repeat(18)).slice(0, 18), 'c-label'],
    [('dur' + ' '.repeat(10)).slice(0, 10), 'c-label'],
    [('modules' + ' '.repeat(34)).slice(0, 34), 'c-label'],
    [('status' + ' '.repeat(11)).slice(0, 11), 'c-label'],
    [('found' + ' '.repeat(8)).slice(0, 8), 'c-label'],
    ['cost', 'c-label'],
  ], W, 'h');

  const rows = [
    wrap(r(false,'r-09f2c1', '2026-05-06 14:31', '2m 41s',  'sast (semgrep+secret+agentic+iac)', 'complete', '18',     '$0.41'), 'a'),
    wrap(r(true ,'r-08e1aa', '2026-05-06 11:08', '6m 02s',  'carlini-threat-hunt + agentic-sast','complete', '11',     '$1.18'), 'b'),
    wrap(r(false,'r-08c0b3', '2026-05-06 09:14', '54s',     'context · threat-model',            'complete', '0 (8 threats)','$0.18'), 'c'),
    wrap(r(false,'r-08be12', '2026-05-06 08:01', '12m 18s', 'agentic-sast (whitebox)',           'partial',  '7',      '$2.04'), 'd'),
    wrap(r(false,'r-08aa44', '2026-05-05 22:11', '1m 03s',  'secret-scan',                       'complete', '0',      '$0.00'), 'e'),
    wrap(r(false,'r-089f01', '2026-05-05 18:42', '4m 12s',  'taint-iris-next (cross-lang)',      'paused',   '4',      '$0.62'), 'f'),
    wrap(r(false,'r-088aa1', '2026-05-05 14:08', '8s',      'codeql',                            'failed',   '—',      '$0.00'), 'g'),
    wrap(r(false,'r-087712', '2026-05-04 16:22', '3m 21s',  'randori (PASTA)',                   'complete', '0 (12 threats)','$0.46'), 'h'),
    wrap(r(false,'r-086301', '2026-05-04 11:01', '11m 02s', 'shinsa (ISO 27001 + NIST)',         'complete', '14 gaps', '$0.94'), 'i'),
    wrap(r(false,'r-084108', '2026-05-03 09:48', '2m 41s',  'prompt-armor (concierge agent)',    'complete', '6',      '$0.71'), 'j'),
  ];

  // detail of focused
  const detail = [
    window.sectionHeader('r-08e1aa · DETAIL', W, 'sd'),
    window.row([['   ', null], m('artifacts   '), p('.kuzushi/runs/r-08e1aa/'), m('  · '), p('summary.json'), m(', '), p('triage.jsonl'), m(', '), p('verify.jsonl'), m(', '), p('poc-h2.txt')], W, 'd1'),
    window.row([['   ', null], m('model       '), p('openai:gpt-4.1'), m(' · '), m('tokens '), p('1.42M in · 184K out'), m(' · '), m('agent steps '), p('221')], W, 'd2'),
    window.row([['   ', null], m('emitted     '), p('11 findings'), m(' · '), p('triaged 11/11'), m(' · '), p('verified 4/11'), m(' · '), p('patched 1/11')], W, 'd3'),
    window.row([['   ', null], m('next        '), a('/replay r-08e1aa'), m('  ·  '), a('/trace r-08e1aa'), m('  ·  '), a('/findings --run r-08e1aa')], W, 'd4'),
  ];

  const lines = [
    window.logLine('in', '14:40:02', [m(' /show runs')], W, 'l1'),
    window.blankRow(W, 'b1'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'rule'),
    ...rows,
    window.blankRow(W, 'b2'),
    ...detail,
  ];

  return (
    <window.TermFrame title="kuzushi · /show runs · 10 visible">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/show runs · 10 of 41 · sort newest', findings: 38,
        keybinds: [['j/k','row'],['enter','open'],['/replay','step'],['/trace','open'],['r','rerun']],
      })}
    </window.TermFrame>
  );
}

window.RunsView = RunsView;
