// /export bundle · package the workspace for sharing

function ExportBundleView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function chk(state, label, hint) {
    const map = { on:[' [✓] ', 'c-success'], off:[' [ ] ', 'c-subtle'], lock:[' [✓] ', 'c-warn'] };
    return [
      [' ', null], map[state], [' ', null],
      [(label + ' '.repeat(40)).slice(0, 36), state === 'off' ? 'c-muted' : 'c-primary'],
      [hint, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in','15:36:01',[m(' /export bundle '), a('--audience triage')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('SHAPE · audience: triage', W, 's1'),
    window.row([T('   '), m('preset  '), p('triage'),
      m(' · others: '), a('reviewer'), m(', '), a('vendor'), m(', '), a('eng-lead'), m(', '),
      a('post-mortem'), m(', '), a('full')], W, 'p1'),
    window.row([T('   '), m('format  '), p('tar.zst'),
      m('  size estimate '), p('~ 8.4 MB'),
      m('  ttl '), p('signed url 7d via /share, or local file forever')], W, 'p2'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('CONTENTS · 9 lanes · ✓ included · [✓] locked', W, 's2'),
    window.row(chk('on',   'findings (open + verified)',           '38 entries → 41 KB · jsonl + per-file md'), W, 'c1'),
    window.row(chk('on',   'threat-model v3',                      'json + rendered md · 42 KB'), W, 'c2'),
    window.row(chk('on',   'top-3 runs (curated)',                 'r-2113 (carlini), r-2115 (patch), r-2117 (verify) · 4.1 MB'), W, 'c3'),
    window.row(chk('on',   'memo · /story --audience triage',      'rendered earlier at 14:46 · 6 KB'), W, 'c4'),
    window.row(chk('off',  'all runs (1842)',                       'turn off by default · 188 MB · /export --include all-runs'), W, 'c5'),
    window.row(chk('off',  'workspace source tree',                 'redact secrets first · operator opt-in'), W, 'c6'),
    window.row(chk('on',   'audit.log slice (24h)',                 '1,842 entries · sha-chained · 482 KB'), W, 'c7'),
    window.row(chk('on',   'allowlist + sandbox profiles',          'reviewer can rerun · 8 KB'), W, 'c8'),
    window.row(chk('lock', 'manifest.toml',                          'always · provenance · sha + ver + actors · 2 KB'), W, 'c9'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('REDACT · scrubber pipeline', W, 's3'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('secret-scan'),
      m('     · 0 secret-shaped strings remain')], W, 'r1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('pii-scrub'),
      m('         · email/cc/ssn shapes redacted to ⟨email⟩, ⟨cc⟩, ⟨ssn⟩')], W, 'r2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('paths-scope'),
      m('     · only paths under '), p('apps/web/agents/'), m(', '), p('apps/api/'), m(' included')], W, 'r3'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('agent-prompts'),
      m('   · sysprompts redacted at /trace; raw versions live only in audit log')], W, 'r4'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('OUTPUT', W, 's4'),
    window.row([T('   '), m('local      '), p('~/Desktop/kuzushi-acme-checkout-2026-05-06-1536.tar.zst')], W, 'o1'),
    window.row([T('   '), m('share url  '), p('/share gen --bundle ⟨id⟩'),  m(' (signed 7d, viewer-only)')], W, 'o2'),
    window.row([T('   '), m('integrity  '), p('sha256:'), p(' a83b…412e')], W, 'o3'),
    window.row([T('   '), m('audit      '), p('audit.log:1849 op=export:bundle audience=triage')], W, 'o4'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','15:36:14',[m(' '), a('y'), m(' build & save · '),
      a('e'), m(' edit lanes · '), a('p'), m(' preview manifest · '), a('s'),
      m(' /share gen on save · '), a('n'), m(' cancel')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /export bundle · triage">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'export', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'export · audience triage · ~ 8.4 MB · 9 lanes', findings: 38,
        promptModule: 'export',
        keybinds: [['y','build'],['e','edit'],['p','preview'],['s','share'],['n','cancel']],
      })}
    </window.TermFrame>
  );
}
window.ExportBundleView = ExportBundleView;
