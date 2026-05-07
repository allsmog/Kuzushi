// X-ray view — peers into the binary / build artifact. Surface map of the
// compiled product: layers, syscalls, opened files/sockets, embedded strings.

function XrayView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  function row(...segs) { return window.row(segs, W); }
  function bar(label, done, total, status, color = 'c-success') {
    const width = 24;
    const pct = total === 0 ? 0 : done / total;
    const filled = Math.round(width * pct);
    const empty = width - filled;
    return [
      [(label + ' '.repeat(20)).slice(0, 20), 'c-primary'],
      [' [', 'c-subtle'],
      ['█'.repeat(filled), color],
      ['░'.repeat(empty), 'c-subtle'],
      ['] ', 'c-subtle'],
      [(`${done}/${total}`).padStart(7), 'c-muted'],
      ['  ', null],
      [status, color],
    ];
  }

  function layer(idx, size, mut, summary) {
    const c = mut === 'mutated' ? 'c-warn' : mut === 'fresh' ? 'c-success' : 'c-muted';
    return [
      [' ', null],
      [`  L${String(idx).padStart(2,'0')}  `, 'c-subtle'],
      [(size + ' '.repeat(10)).slice(0, 10), 'c-primary'],
      [(mut + '   ').slice(0, 9), c],
      [summary, 'c-primary'],
    ];
  }

  function syscall(name, count, suspicious, where) {
    return [
      [' ', null],
      [(name + ' '.repeat(20)).slice(0, 18), 'c-accent'],
      [String(count).padStart(5), 'c-primary'],
      ['  ', null],
      [suspicious ? '★ review' : '  ok    ', suspicious ? 'c-warn' : 'c-muted'],
      ['  ', null],
      [where, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in',  '15:33:01', [m(' /use '), a('x-ray')], W, 'l1'),
    window.logLine('in',  '15:33:09', [m(' /run '), a('--target oci://acme/checkout-api:1.42')], W, 'l2'),
    window.logLine('run', '15:33:09', [m(' x-ray:run · pulling image · 41 layers · '), p('312 MB')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('layers              ', 41, 41,    'done',          'c-success')], W, 'p1'),
    window.row([T('   '), ...bar('strings extract     ', 184237, 184237, 'done · 12k unique', 'c-success')], W, 'p2'),
    window.row([T('   '), ...bar('syscalls (static)   ',   89,  89, 'done',          'c-success')], W, 'p3'),
    window.row([T('   '), ...bar('open-files trace    ',   42,  42, 'done',          'c-success')], W, 'p4'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('LAYERS · top 7', W, 'sec-l'),
    window.row(layer( 1, '188 MB', 'base',     'debian:trixie-slim · '), W, 'l1a'),
    window.row(layer( 2, '  62 MB', 'base',     'apt-get install ca-certificates curl'), W, 'l2a'),
    window.row(layer(14, '  12 MB', 'mutated',  'COPY --from=builder /out/checkout-api /usr/bin/'), W, 'l3a'),
    window.row(layer(15, '   4 MB', 'mutated',  'COPY config/prod.toml /etc/acme/'), W, 'l4a'),
    window.row(layer(28, ' 312 KB', 'fresh',    'RUN useradd app && chown -R app /var/lib/acme'), W, 'l5a'),
    window.row(layer(36, '  18 KB', 'fresh',    'COPY healthcheck.sh /usr/local/bin/'), W, 'l6a'),
    window.row(layer(41, '   2 KB', 'fresh',    'CMD ["/usr/bin/checkout-api","--config","/etc/acme/prod.toml"]'), W, 'l7a'),
    window.blankRow(W, 'b3'),

    window.sectionHeader('SYSCALLS (static)', W, 'sec-s'),
    window.row(syscall('execve',     12, true,  'spawned shells in healthcheck.sh + worker.py'), W, 's1'),
    window.row(syscall('socket',      4, false, 'tcp listen 8080, outbound 443/5432'), W, 's2'),
    window.row(syscall('open',     3812, false, '~12 unique paths · /etc/acme/, /var/lib/acme/'), W, 's3'),
    window.row(syscall('ptrace',     1, true,  'present but unused — surface to drop'), W, 's4'),
    window.row(syscall('mount',      0, false, '—'), W, 's5'),
    window.blankRow(W, 'b4'),

    window.sectionHeader('STRINGS OF INTEREST · 4', W, 'sec-st'),
    window.row([T('   '), [' ! ', 'c-warn'], p('https://staging.acme-internal.local/grafana'), m('  in '), p('L14'), m(' · '), w('staging URL in prod image')], W, 'st1'),
    window.row([T('   '), [' ! ', 'c-warn'], p('TODO: rotate this before launch'),             m('  in '), p('L14'), m(' · build artifact comment')], W, 'st2'),
    window.row([T('   '), [' · ', 'c-subtle'], p('checkout-api 1.42.0+sha.7c9aa11'),             m('  in '), p('L14'), m(' · benign version')], W, 'st3'),
    window.row([T('   '), [' · ', 'c-subtle'], p('CN=acme-checkout-svc'),                         m('         in '), p('L15'), m(' · cert subject')], W, 'st4'),
    window.blankRow(W, 'b5'),

    window.logLine('agent', '15:33:48', [
      m(' surface to drop: '), a('ptrace'), m(', '), a('execve'), m(' (no shells in steady state). 2 strings warrant scrub before re-tag.'),
    ], W, 'l-end'),
    window.logLine('log', '15:33:48', [m(' wrote '), p('x-ray/checkout-api-1.42.json'), m(' · '), p('218 KB')], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · x-ray · oci://acme/checkout-api:1.42">
      {window.statusStrip({ target: 'oci://acme/checkout-api:1.42', ctx: 'image-pull', module: 'x-ray', cost: '$0.06' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'x-ray (done) · 41 layers · 4 strings flagged', findings: 2,
        promptModule: 'x-ray',
        keybinds: [
          ['/show', 'layer L14 | strings'], ['/x-ray', 'read | diff'],
          ['/use', 'patch'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.XrayView = XrayView;
