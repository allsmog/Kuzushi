// /cost — spend ledger.

function CostView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function bar(label, used, budget, color) {
    const w = 30;
    const pct = Math.min(1, used / budget);
    const fill = Math.round(w * pct);
    return [
      [(label + ' '.repeat(18)).slice(0, 18), 'c-primary'],
      [' [', 'c-subtle'],
      ['█'.repeat(fill), color],
      ['░'.repeat(w - fill), 'c-subtle'],
      ['] ', 'c-subtle'],
      [('$' + used.toFixed(2)).padStart(8), 'c-primary'],
      [' / ', 'c-muted'],
      [('$' + budget.toFixed(2)).padStart(8), 'c-muted'],
      [' ', null],
      [(Math.round(pct * 100) + '%').padStart(5), pct > 0.85 ? 'c-warn' : 'c-muted'],
    ];
  }

  function row(focused, mod, calls, tokIn, tokOut, cost) {
    const mCell  = (mod + ' '.repeat(22)).slice(0, 22);
    const cCell  = (calls + ' '.repeat(8)).slice(0, 8);
    const inCell = (tokIn + ' '.repeat(14)).slice(0, 14);
    const outCell= (tokOut + ' '.repeat(14)).slice(0, 14);
    const $Cell  = ('$' + cost).padStart(8);
    if (focused) {
      const text = ' ' + mCell + cCell + inCell + outCell + $Cell + ' ';
      return <span className="row" key={mod}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return [
      ['    ', null],
      [mCell, 'c-accent'],
      [cCell, 'c-muted'],
      [inCell, 'c-muted'],
      [outCell, 'c-muted'],
      [$Cell, 'c-primary'],
    ];
  }

  const wrap = (v, k) => Array.isArray(v) ? window.row(v, W, k) : v;

  const heads = window.row([
    ['    ', null],
    [('module' + ' '.repeat(22)).slice(0, 22), 'c-label'],
    [('calls' + ' '.repeat(8)).slice(0, 8), 'c-label'],
    [('tok in' + ' '.repeat(14)).slice(0, 14), 'c-label'],
    [('tok out' + ' '.repeat(14)).slice(0, 14), 'c-label'],
    ['cost', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','14:48:00', [m(' /cost')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('BUDGETS', W, 'sb'),
    window.row([T('   '), ...bar('today           ', 1.42, 5.00, 'c-success')], W, 'b-d'),
    window.row([T('   '), ...bar('this week       ', 6.18, 25.00, 'c-success')], W, 'b-w'),
    window.row([T('   '), ...bar('this month      ', 21.40, 100.00, 'c-success')], W, 'b-m'),
    window.row([T('   '), ...bar('this run        ', 0.41, 5.00, 'c-success')], W, 'b-r'),
    window.row([T('   '), ...bar('agentic-sast    ', 4.18, 5.00, 'c-warn')], W, 'b-a'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('BY MODULE · last 7 days', W, 'sm'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'r'),
    wrap(row(false,'agentic-sast',         '94',  '8.4M',   '912K',  '4.18'), 'a'),
    wrap(row(true ,'carlini-threat-hunt',  '22',  '3.1M',   '241K',  '1.94'), 'b'),
    wrap(row(false,'threat-model',         '14',  '612K',   '188K',  '0.84'), 'c'),
    wrap(row(false,'randori',              '8',   '418K',   '94K',   '0.62'), 'd'),
    wrap(row(false,'taint-iris-next',      '11',  '892K',   '64K',   '0.58'), 'e'),
    wrap(row(false,'shinsa',               '6',   '301K',   '88K',   '0.41'), 'f'),
    wrap(row(false,'prompt-armor',         '12',  '218K',   '54K',   '0.38'), 'g'),
    wrap(row(false,'verify',               '24',  '188K',   '24K',   '0.21'), 'h'),
    wrap(row(false,'patch',                '8',   '94K',    '32K',   '0.14'), 'i'),
    wrap(row(false,'triage',               '38',  '141K',   '12K',   '0.10'), 'j'),
    window.blankRow(W, 'b3'),
    window.logLine('agent','14:48:01', [
      [' ', null],
      ['agentic-sast', 'c-warn'], m(' is at '), ['83%', 'c-warn'], m(' of its module budget — '),
      ['/set budget.agentic-sast 8.00', 'c-accent'], m(' to extend, or it will halt at $5.00'),
    ], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /cost · spend ledger">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$1.42' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/cost · today $1.42 / $5.00 · this week $6.18 / $25.00', findings: 38,
        keybinds: [['j/k','row'],['/set budget.*','adjust'],['/auth','providers'],['/back','catalog']],
      })}
    </window.TermFrame>
  );
}

window.CostView = CostView;
