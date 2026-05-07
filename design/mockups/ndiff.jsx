// Ndiff view — pull a CVE patch, lift its fix pattern, hunt the inverse
// (un-fixed shapes) across our codebase.

function NdiffView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  function diff(kind, text, key) {
    const pfx = kind === 'add' ? '+ ' : kind === 'del' ? '- ' : '  ';
    const cls = kind === 'add' ? 'c-success' : kind === 'del' ? 'c-danger' : 'c-muted';
    return window.row([T('     '), [pfx, cls], [text, cls]], W, key);
  }

  function hit(conf, file, line, snippet) {
    const c = conf >= 0.85 ? 'c-danger' : conf >= 0.6 ? 'c-warn' : 'c-muted';
    return [
      [' ', null],
      [(conf.toFixed(2) + '   ').slice(0, 6), c],
      [(file + ':' + line + ' '.repeat(40)).slice(0, 38), 'c-muted'],
      [snippet, 'c-primary'],
    ];
  }

  const lines = [
    window.logLine('in',  '15:08:18', [m(' /use '), a('ndiff')], W, 'l1'),
    window.logLine('in',  '15:08:24', [m(' /run '), a('fetch-cve CVE-2024-21626')], W, 'l2'),
    window.logLine('run', '15:08:24', [m(' ndiff:fetch-cve · pulling NVD entry · resolving fix commit')], W, 'l3'),
    window.logLine('ok',  '15:08:25', [m(' '), a('CVE-2024-21626'), m(' · runc fd leak → host fs · fix in '), p('opencontainers/runc@5e6a160')], W, 'l4'),
    window.blankRow(W, 'b1'),

    window.sectionHeader('UPSTREAM FIX DIFF · runc · libcontainer/init.go', W, 'sec-d'),
    diff('ctx', '@@ -64,6 +64,11 @@ func startInitialization(', 'd0'),
    diff('ctx', '    if err := setupRootfs(...); err != nil {', 'd1'),
    diff('add', '+   if err := closeFdsFrom(\"/proc/self/fd\", 3); err != nil {', 'd2'),
    diff('add', '+       return fmt.Errorf(\"close inherited fds: %w\", err)', 'd3'),
    diff('add', '+   }', 'd4'),
    diff('ctx', '    if err := finalizeNamespace(...); err != nil {', 'd5'),
    diff('ctx', "        return err", 'd6'),
    diff('ctx', " }", 'd7'),
    window.blankRow(W, 'b2'),

    window.logLine('in',  '15:08:33', [m(' /run '), a('extract-fix-pattern')], W, 'l5'),
    window.logLine('flow','15:08:35', [m(' lifted pattern: '), p('exec()-into-container without explicit FD-close from /proc/self/fd')], W, 'l6'),
    window.blankRow(W, 'b3'),

    window.logLine('in',  '15:08:40', [m(' /run '), a('hunt-variants --invert')], W, 'l7'),
    window.logLine('run', '15:08:40', [m(' ndiff:hunt-variants · looking for un-fixed shapes')], W, 'l8'),
    window.blankRow(W, 'b4'),

    window.sectionHeader('HUNT · 4 candidate sites in our code', W, 'sec-h'),
    window.row(hit(0.92, 'jobs/runner', '142', 'cmd.Start() inside container without FD scrub'), W, 'h1'),
    window.row(hit(0.81, 'tools/exec',  '54',  'exec.Command(...).Run() in lxc-spawn shim'), W, 'h2'),
    window.row(hit(0.55, 'apps/api/sandbox.rs', '88', 'cgroups namespace enter — go through libcontainer wrapper'), W, 'h3'),
    window.row(hit(0.34, 'tests/sandbox/main.go', '12', 'looks like a test fixture · low priority'), W, 'h4'),
    window.row([T('   '), m('   ▸ '), a('/promote h1 h2'), m(' as findings · '), a('/show diff h1'), m(' for upstream-vs-ours side-by-side')], W, 'h-cta'),
    window.blankRow(W, 'b5'),

    window.logLine('agent', '15:08:54', [
      m(' h1 is the same shape as the runc fix — '), w('exact'), m('. h2 wraps it indirectly. h3 is already mitigated.'),
    ], W, 'l-end'),
    window.logLine('log', '15:08:54', [m(' wrote '), p('.kuzushi/runs/.../ndiff.json'), m(' · pattern at '), p('.kuzushi/patterns/runc-fd-leak.yml')], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · ndiff · CVE-2024-21626 → hunt-variants">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'ndiff', cost: '$0.07' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'ndiff (done) · 4 hits · 2 high-conf', findings: 2,
        promptModule: 'ndiff',
        keybinds: [
          ['/promote', 'h1 h2'], ['/show', 'diff h1'],
          ['/use', 'patch h1'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.NdiffView = NdiffView;
