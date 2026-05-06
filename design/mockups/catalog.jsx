// Catalog view — entry view, four categories, growing-console aesthetic.
// No DAG column. Single recommended-next "▸" line. j/k focus.

function CatalogView() {
  const W = window.W120;

  // Module rows: [id, desc, focused?]
  function modRow(id, desc, opts = {}) {
    const focused = !!opts.focused;
    const indent = focused ? '  ▌ ' : '    ';
    const idCell = (id + ' '.repeat(40)).slice(0, 22);
    const descW  = W - indent.length - idCell.length - 2;
    const descCell = (desc + ' '.repeat(200)).slice(0, descW);
    if (focused) {
      return (
        <span className="row" key={id}>
          <span className="c-accent">{'  ▌'}</span>
          <span className="c-sel">{' ' + idCell + descCell + '  '}</span>
        </span>
      );
    }
    return (
      <span className="row" key={id}>
        <span>{indent}</span>
        <span className="c-primary">{idCell}</span>
        <span className="c-muted">{descCell}</span>
        <span>{'  '}</span>
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
    modRow('semgrep',      'pattern-based SAST over the workspace'),
    modRow('sast',         'umbrella SAST executor (semgrep + secret-scan + agentic)', { focused: true }),
    modRow('codeql',       'CodeQL CLI scan (requires codeql binary)'),
    modRow('agentic-sast', 'LLM-driven dataflow + variant hunt'),
    modRow('carlini-threat-hunt', 'Carlini-style adversarial threat hunt over the codebase'),
    modRow('secret-scan',  'deterministic secret detector'),
    window.blankRow(W, 'o-end'),
  ];
  const intel = [
    catHead('INTEL', 'build context, recon, and threat model the operator reads first'),
    modRow('context',      'index workspace into .kuzushi/context-snapshot.json'),
    modRow('recon',        'nmap · subdomain · http-fingerprint'),
    modRow('threat-model', 'build / read .kuzushi/threat-model.json'),
    modRow('randori',      'PASTA threat model w/ ATT&CK + KEV intel'),
    window.blankRow(W, 'i-end'),
  ];
  const gov = [
    catHead('GOVERNANCE', 'configuration, allowlists, audit trails — operator surface'),
    modRow('config',       'effective ~/.kuzushi config + auth state'),
    modRow('shinsa',       'ISO 27001 / NIST / SOC 2 compliance scan'),
    modRow('tob',          'Trail of Bits audit skills'),
    window.blankRow(W, 'g-end'),
  ];
  const def = [
    catHead('DEFENSE', 'triage, verify, and patch findings emitted by OFFENSE'),
    modRow('triage',       'LLM triage + verdict over persisted findings'),
    modRow('verify',       'reproduce + confirm a finding'),
    modRow('patch',        'suggest a fix patch for a verified finding'),
    modRow('findings',     'list / filter persisted findings'),
  ];

  const next = window.row([
    [' ', null],
    ['▸ NEXT  ', 'c-warn'],
    ['Run ', 'c-primary'],
    ['sast:scan', 'c-accent'],
    [' against ', 'c-primary'],
    ['~/work/acme-checkout', 'c-primary'],
    ['  — never run here, 0 findings on record', 'c-muted'],
  ], W, 'next');

  return (
    <window.TermFrame title="kuzushi · catalog · 120×40">
      {window.statusStrip({ target: '~/work/acme-checkout' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {next}
      {window.blankRow(W, 'b2')}
      {window.ruleRow(W, 'r2')}
      {window.blankRow(W, 'b3')}
      {offense}
      {intel}
      {gov}
      {def}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'idle', findings: 0, mod: null,
        keybinds: [
          ['j/k', 'row'], ['1..4', 'jump category'],
          ['enter', '/use'], ['/scan', 'run sast:scan'],
          ['?', 'help'],
        ],
      })}
    </window.TermFrame>
  );
}

window.CatalogView = CatalogView;
