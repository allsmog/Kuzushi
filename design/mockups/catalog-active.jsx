// catalog · with running + recent overlay

function CatalogActiveView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function modRow(id, desc, opts = {}) {
    const focused = !!opts.focused;
    const idCell = (id + ' '.repeat(40)).slice(0, 22);
    const descCell = (desc + ' '.repeat(180)).slice(0, 60);
    const status = opts.status || '';
    const sCol = opts.statusCol || 'c-muted';
    const indent = focused ? '  ▌' : '   ';
    if (focused) {
      const text = ' ' + idCell + descCell + (status ? ('· ' + status + ' ').padEnd(20, ' ') : '');
      return <span className="row" key={id}><span className="c-accent">{indent}</span><span className="c-sel">{text}</span></span>;
    }
    return (
      <span className="row" key={id}>
        <span>{indent + ' '}</span>
        <span className="c-primary">{idCell}</span>
        <span className="c-muted">{descCell}</span>
        {status ? <span className={sCol}>{' · ' + status}</span> : null}
      </span>
    );
  }

  function catHead(name, blurb) {
    return window.row([
      [' ', null],
      [`── ${name} `, 'c-label'],
      [`${blurb} `, 'c-muted'],
      ['─'.repeat(Math.max(0, W - 1 - 4 - name.length - 1 - blurb.length - 1)), 'c-subtle'],
    ], W, name);
  }

  const offense = [
    catHead('OFFENSE', 'find vulnerabilities by scanning code, deps, and runtime surface'),
    modRow('semgrep',      'pattern-based SAST',                              { status: '14:32 · 18 hits · 2 critical', statusCol: 'c-success' }),
    modRow('sast',         'umbrella SAST executor',                          { status: 'now · running r-2118 · 49/120', statusCol: 'c-warn',  focused: true }),
    modRow('codeql',       'CodeQL CLI scan',                                 { status: 'binary missing',               statusCol: 'c-danger' }),
    modRow('agentic-sast', 'LLM-driven dataflow + variant hunt',              { status: 'now · part of r-2118',          statusCol: 'c-warn' }),
    modRow('carlini-threat-hunt', 'Carlini-style adversarial threat hunt',    { status: '14:08 · 1 critical (F-0012)',   statusCol: 'c-success' }),
    modRow('secret-scan',  'deterministic secret detector',                   { status: '15:40 · 2 live (F-0061, F-0062)', statusCol: 'c-danger' }),
    window.blankRow(W, 'o-end'),
  ];
  const intel = [
    catHead('INTEL', 'build context, recon, and threat model the operator reads first'),
    modRow('context',      'index workspace into context-snapshot.json',       { status: '11:58 · fresh',                statusCol: 'c-success' }),
    modRow('recon',        'nmap · subdomain · http-fingerprint',              { status: 'never run · external-only',    statusCol: 'c-muted' }),
    modRow('threat-model', 'build / read .kuzushi/threat-model.json',          { status: '15:12 · v3 applied',           statusCol: 'c-success' }),
    modRow('randori',      'PASTA threat model w/ ATT&CK + KEV intel',          { status: '14:24 · 4 stories pivoted',   statusCol: 'c-success' }),
    window.blankRow(W, 'i-end'),
  ];
  const gov = [
    catHead('GOVERNANCE', 'configuration, allowlists, audit trails — operator surface'),
    modRow('config',       'effective config + auth state',                    { status: 'fresh · 3 overrides',          statusCol: 'c-muted' }),
    modRow('shinsa',       'ISO 27001 / NIST / SOC 2 compliance scan',          { status: 'plugin missing',               statusCol: 'c-danger' }),
    modRow('tob',          'Trail of Bits audit skills',                       { status: 'skills dir unset',             statusCol: 'c-danger' }),
    modRow('vuln-scout',   'audit ledger',                                      { status: '15:28 · chain ok · 25 events',statusCol: 'c-success' }),
    window.blankRow(W, 'g-end'),
  ];
  const def = [
    catHead('DEFENSE', 'triage, verify, and patch findings emitted by OFFENSE'),
    modRow('triage',       'LLM triage + verdict over persisted findings',     { status: '15:20 · 7 pending',            statusCol: 'c-warn' }),
    modRow('verify',       'reproduce + confirm a finding',                    { status: '15:26 · F-0012 sandbox spinning', statusCol: 'c-warn' }),
    modRow('patch',        'suggest a fix patch for a verified finding',       { status: '15:22 · F-0002 verified-fixed', statusCol: 'c-success' }),
    modRow('findings',     'list / filter persisted findings',                  { status: '47 total · 3 critical · 14 high', statusCol: 'c-muted' }),
  ];

  const next = window.row([
    [' ', null],
    ['▸ NEXT  ', 'c-warn'],
    ['Resume ', 'c-primary'],
    ['r-2118', 'c-accent'],
    [' (agentic-sast 49/120, paused at $2.50 cap) ', 'c-primary'],
    ['  — raise $0.50 to finish or finalize best-effort', 'c-muted'],
  ], W, 'next');

  const ribbon = window.row([
    [' ', null],
    [' running ', 'c-warn'],
    ['  ', null],
    ['r-2118 ', 'c-accent'], ['agentic-sast ', 'c-primary'],
    ['frame ', 'c-muted'], ['49/120 ', 'c-primary'],
    ['· ', 'c-subtle'],
    ['$0.18/$2.50 ', 'c-primary'],
    ['· findings ', 'c-muted'], ['+9 ', 'c-success'],
    ['  ', null],
    [' tail ', 'c-accent'], ['/tail r-2118  ', 'c-muted'],
    [' pause ', 'c-accent'], ['/pause r-2118  ', 'c-muted'],
    [' attach ', 'c-accent'], ['/agent', 'c-muted'],
  ], W, 'ribbon');

  return (
    <window.TermFrame title="kuzushi · catalog · live · 1 running · 47 findings">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$6.36' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {ribbon}
      {window.blankRow(W, 'b2')}
      {next}
      {window.blankRow(W, 'b3')}
      {window.ruleRow(W, 'r2')}
      {window.blankRow(W, 'b4')}
      {offense}
      {intel}
      {gov}
      {def}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'idle · 1 background run', findings: 47, mod: null,
        keybinds: [
          ['j/k', 'row'], ['1..4', 'jump category'],
          ['enter', '/use'], ['/tail', 'r-2118'],
          ['?', 'help'],
        ],
      })}
    </window.TermFrame>
  );
}
window.CatalogActiveView = CatalogActiveView;
