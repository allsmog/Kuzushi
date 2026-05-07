// runs-list · /runs · ledger of completed + active runs

function RunsListView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function runRow(focused, id, when, mod, target, dur, findings, status, statusCls) {
    const cells = [
      [' ' + id + ' ', 'c-accent'],
      ['  ', null],
      [when, 'c-subtle'],
      ['  ', null],
      [(mod + ' '.repeat(14)).slice(0,14), 'c-primary'],
      [(target + ' '.repeat(28)).slice(0,28), 'c-muted'],
      [(dur + ' '.repeat(7)).slice(0,7), 'c-muted'],
      [(findings + ' '.repeat(10)).slice(0,10), 'c-warn'],
      [' ' + status + ' ', statusCls],
    ];
    if (focused) {
      const text = ' ' + id + '  ' + when + '  ' + (mod + ' '.repeat(14)).slice(0,14)
        + (target + ' '.repeat(28)).slice(0,28) + (dur + ' '.repeat(7)).slice(0,7)
        + (findings + ' '.repeat(10)).slice(0,10) + ' ' + status;
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([T('   '), ...cells], W, id);
  }

  const lines = [
    window.logLine('in','17:02:01',[m(' /runs ')], W, 'l1'),
    window.row([T('  '), m('114 runs in ledger '),
      m(' · filter '), p('--mod sast'), m(' · '),
      p('--since 7d'), m(' · '),
      p('--target acme-*'), m(' · '),
      p('--has-findings'), m(' · '),
      p('--failed')], W, 'h0'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), [' RUN-ID  ', 'c-subtle'], [' WHEN          ', 'c-subtle'],
      [' MODULE         ', 'c-subtle'], [' TARGET                      ', 'c-subtle'],
      [' DUR    ', 'c-subtle'], [' FINDINGS  ', 'c-subtle'], [' STATUS', 'c-subtle']], W, 'hd'),
    window.ruleRow(W, 'r0'),
    runRow(true,  'r-0114', '4m  ago     ', 'agentic-sast', 'acme-checkout',           '12m02s', '7 (1 CR)', 'COMPLETE',  'c-success'),
    runRow(false, 'r-0113', '14m ago     ', 'verify',       'acme-checkout · F-0012',   '0m31s', 'verified', 'COMPLETE',  'c-success'),
    runRow(false, 'r-0112', '22m ago     ', 'patch',        'acme-checkout · F-0012',   '1m48s', 'staged',   'STAGED',    'c-accent'),
    runRow(false, 'r-0111', '1h  ago     ', 'sast',         'acme-checkout',           '4m12s', '38',       'COMPLETE',  'c-success'),
    runRow(false, 'r-0110', '1h  ago     ', 'recon',        'acme.example.com',        '2m04s', '—',        'COMPLETE',  'c-success'),
    runRow(false, 'r-0109', '3h  ago     ', 'carlini',      'gpt-4o-mini',             '17m22s','3 (1 HI)', 'COMPLETE',  'c-success'),
    runRow(false, 'r-0108', '4h  ago     ', 'ndiff',        'libxml2 · CVE-2024-44331','9m18s', '2',        'COMPLETE',  'c-success'),
    runRow(false, 'r-0107', '5h  ago     ', 'agentic-sast', 'acme-payments',           '8m41s', '—',        'NO HITS',   'c-muted'),
    runRow(false, 'r-0106', 'yest 18:02  ', 'iac-scan',     'infra/terraform',         '1m11s', '4 (2 HI)', 'COMPLETE',  'c-success'),
    runRow(false, 'r-0105', 'yest 16:44  ', 'sast',         'acme-checkout',           '—',     '—',        'BUDGET STOP','c-danger'),
    runRow(false, 'r-0104', 'yest 14:22  ', 'verify',       'acme-checkout · F-0008',   '0m22s', 'flake',    'FAILED',    'c-danger'),
    runRow(false, 'r-0103', 'yest 11:09  ', 'taint-iris',   'acme-checkout',           '6m02s', '11',       'COMPLETE',  'c-success'),
    runRow(false, 'r-0102', '2d  ago     ', 'threat-model', 'acme-checkout',           '3m44s', '—',        'COMPLETE',  'c-success'),
    runRow(false, 'r-0101', '2d  ago     ', 'vuln-scout',   'acme-checkout · deps',    '0m48s', '6',        'COMPLETE',  'c-success'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('AGGREGATE · last 7 days', W, 's1'),
    window.row([T('   '), m('   '), p('runs    '), a('  47'), m('     '),
      p('compute '), a('  4h 18m'), m('     '),
      p('cost    '), a('  $11.27'), m('     '),
      p('findings'), a('  214'), m('     '),
      p('verified-true'), a('  82%')], W, 'a1'),
    window.blankRow(W, 'b3'),
    window.logLine('flow','17:02:14',[m(' '), a('j/k'), m(' run · '),
      a('enter'), m(' inspect · '),
      a('r'), m(' replay · '),
      a('R'), m(' rerun (same args) · '),
      a('d'), m(' diff with prev · '),
      a('/'), m(' filter · '),
      a('Esc'), m(' close')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /runs · 114 in ledger">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'runs', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'runs · 114 ledger entries · 47 in last 7d',
        findings: 214,
        promptModule: 'runs',
        keybinds: [['j/k','run'],['enter','inspect'],['r','replay'],['R','rerun'],['d','diff'],['/','filter']],
      })}
    </window.TermFrame>
  );
}
window.RunsListView = RunsListView;
