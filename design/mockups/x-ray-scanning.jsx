// x-ray · scanning state (in flight)

function XrayScanningView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function bar(label, done, total, status, color) {
    const w = 22;
    const pct = total === 0 ? 0 : done / total;
    const filled = Math.round(w * pct);
    return [
      [(label + ' '.repeat(20)).slice(0, 18), 'c-primary'],
      [' [', 'c-subtle'],
      ['█'.repeat(filled), color || 'c-success'],
      ['░'.repeat(w - filled), 'c-subtle'],
      ['] ', 'c-subtle'],
      [(`${done}/${total}`).padStart(11), 'c-muted'],
      ['  ', null],
      [status, color || 'c-success'],
    ];
  }

  function layer(idx, sha, mb, what, status) {
    const sMap = {
      done:[' ✓ ', 'c-success'],
      now: [' ⏵ ', 'c-warn'],
      wait:[' · ', 'c-subtle'],
    };
    return [
      [' ', null],
      [(' ' + idx + ' ').slice(0, 4), 'c-subtle'],
      sMap[status],
      [(sha + ' '.repeat(14)).slice(0, 12), 'c-accent'],
      [(mb + ' '.repeat(10)).slice(0, 8), 'c-muted'],
      [what, status === 'now' ? 'c-warn' : 'c-primary'],
    ];
  }

  const lines = [
    window.logLine('in','15:14:01',[m(' /run x-ray:scan '), a('{"image":"acme/checkout-api:v1.84.2"}')], W, 'l1'),
    window.logLine('run','15:14:01',[m(' pulling manifest from '), p('ghcr.io'), m(' · 12 layers · 412 MB')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('layers              ',  8, 12, 'unpacking layer 9 …',  'c-warn')], W, 'p1'),
    window.row([T('   '), ...bar('files indexed       ', 41840, 62000, 'sha256 + ar/elf id',  'c-warn')], W, 'p2'),
    window.row([T('   '), ...bar('cve match (kev)     ',  84, 142, 'matching against ~/.kuzushi/v2/kb/kev', 'c-warn')], W, 'p3'),
    window.row([T('   '), ...bar('binary surface (elf)',  18, 22,  'syms · capabilities · setuid', 'c-warn')], W, 'p4'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('LAYERS', W, 's1'),
    window.row(layer( 1, 'sha:a83b…', '24 MB',  'distroless/static-debian12 · base',                                         'done'), W, 'L1'),
    window.row(layer( 2, 'sha:7f10…', '0.4 MB', 'add user nonroot (uid 65532) · ENTRYPOINT [/api]',                          'done'), W, 'L2'),
    window.row(layer( 3, 'sha:4d22…', '14 MB',  'libc6 · openssl 3.2.1',                                                     'done'), W, 'L3'),
    window.row(layer( 4, 'sha:911e…', '6 MB',   'tini 0.19.0',                                                               'done'), W, 'L4'),
    window.row(layer( 5, 'sha:ca08…', '88 MB',  'rustup toolchain 1.84 · build env',                                          'done'), W, 'L5'),
    window.row(layer( 6, 'sha:f422…', '142 MB', 'cargo build --release · target/release/api · STRIPPED, but with .debug_str','done'), W, 'L6'),
    window.row(layer( 7, 'sha:b14a…', '12 MB',  'config /etc/kuzushi/api.toml · 644',                                         'done'), W, 'L7'),
    window.row(layer( 8, 'sha:e90c…', '4 MB',   'nss/ca-certs roll',                                                           'done'), W, 'L8'),
    window.row(layer( 9, 'sha:ab38…', '38 MB',  'add postgres-client + curl (debug only?)',                                   'now'),  W, 'L9'),
    window.row(layer(10, 'sha:c004…', '0.2 MB', 'pending …',                                                                  'wait'), W, 'L10'),
    window.row(layer(11, 'sha:?',     '?',      'pending …',                                                                  'wait'), W, 'L11'),
    window.row(layer(12, 'sha:?',     '?',      'pending …',                                                                  'wait'), W, 'L12'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('LIVE FLAGS', W, 's2'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('layer 9'), m(' adds '), p('curl + psql'),
      m(' to a non-build image · usually shipped only to debug images')], W, 'f1'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('layer 6'), m(' binary has '), p('.debug_str'),
      m(' kept · 18 MB of symbol leak · helps an attacker read sources')], W, 'f2'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('CVE-2026-2941'), m(' · libpq 16.1 · matches layer 9 (just unpacked)')], W, 'f3'),
    window.blankRow(W, 'b4'),
    window.logLine('agent','15:14:38',[
      m(' '), [' early call ', 'c-warn'], m(' the curl+psql add looks like the ssh-into-prod debug image leaked into v1.84.2 · cite '),
      p('layer 9'),
    ], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · x-ray · acme/checkout-api:v1.84.2 (in flight)">
      {window.statusStrip({ target: 'acme/checkout-api:v1.84.2', ctx: 'building', module: 'x-ray', cost: '$0.08' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'x-ray · 8/12 layers · matching kev', findings: 38,
        promptModule: 'x-ray',
        keybinds: [['/pause','halt'],['l','select layer'],['?','agent'],['/back','catalog']],
      })}
    </window.TermFrame>
  );
}
window.XrayScanningView = XrayScanningView;
