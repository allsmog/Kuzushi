// Secret-scan view — deterministic detector. Walks blob history + working
// tree. Entropy + rule library. No findings on this run, but a couple
// suspect strings flagged for human review.

function SecretScanView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

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

  function suspect(rule, score, where, preview) {
    return [
      [' ', null],
      [('SUSPECT' + '   '), 'c-warn'],
      [(rule + ' '.repeat(40)).slice(0, 32), 'c-accent'],
      [('entropy ' + score.toFixed(2) + ' '.repeat(20)).slice(0, 16), 'c-muted'],
      [(where + ' '.repeat(40)).slice(0, 32), 'c-muted'],
      [preview, 'c-primary'],
    ];
  }

  const lines = [
    window.logLine('in', '14:09:12', [m(' /use '), a('secret-scan')], W, 'l1'),
    window.logLine('in', '14:09:18', [m(' /run '), a('--include-history --since v1.0.0')], W, 'l2'),
    window.logLine('run', '14:09:18', [m(' secret-scan · '), p('1284'), m(' blobs · '), p('186'), m(' commits since v1.0.0')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('rules · regex       ', 1284, 1284, 'done · 0 hits', 'c-success')], W, 'p1'),
    window.row([T('   '), ...bar('rules · entropy     ', 1284, 1284, 'done · 4 suspects', 'c-warn')], W, 'p2'),
    window.row([T('   '), ...bar('rules · git history ', 186, 186, 'done · 0 hits', 'c-success')], W, 'p3'),
    window.row([T('   '), ...bar('allowlist           ', 12, 12, 'applied · 2 ignored', 'c-success')], W, 'p4'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('CONFIRMED · 0 plaintext secrets', W, 'sec1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m(' no aws/gcp/stripe/openai patterns matched · no high-entropy in committed history')], W, 'ok1'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('SUSPECTS · 4 · need a human', W, 'sec2'),
    window.row(suspect('high-entropy-string',     5.42, 'apps/web/build/main.js:1', 'const M="aGVsbG9... " (1.4kb minified blob)'), W, 'su1'),
    window.row(suspect('looks-like-jwt',          4.91, 'tests/fixtures/auth.json:3', '"token":"eyJhbGciOiJIUzI1NiJ9..."'), W, 'su2'),
    window.row(suspect('base64-with-padding',     5.18, 'docs/decisions/2024-08-rotate.md:42', 'old key was: ABCD1234EFGH5678…'), W, 'su3'),
    window.row(suspect('high-entropy-string',     4.66, 'infra/k8s/configmap.yaml:18', 'public_key_pem: |\\n  -----BEGIN PUBLIC...'), W, 'su4'),
    window.row([T('   '), m('   ▸ '), a('/use prompt-armor'), m(' for an LLM second-pass on suspects')], W, 'su-cta'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('ALLOWLIST · 2 ignored', W, 'sec3'),
    window.row([T('   '), m('   '), p('tests/fixtures/stripe-test-key.txt'), m(' — '), w('# kuzushi:allow stripe-test')], W, 'al1'),
    window.row([T('   '), m('   '), p('docs/setup.md:88'),                  m(' — '), w('# kuzushi:allow placeholder')], W, 'al2'),
    window.blankRow(W, 'b5'),
    window.logLine('ok', '14:09:34', [
      m(' wrote '), p('.kuzushi/v2/raw/secret-scan-2026-05-06T14-09.json'),
      m(' · '), p('clean ✓'),
    ], W, 'l-end'),
  ];

  return (
    <window.TermFrame title="kuzushi · secret-scan · /run --include-history">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'secret-scan', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'secret-scan (done) · 0 confirmed · 4 suspects', findings: 0,
        promptModule: 'secret-scan',
        keybinds: [
          ['/use', 'prompt-armor'], ['/show', 'suspects'],
          ['/allow', 'preview.js'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.SecretScanView = SecretScanView;
