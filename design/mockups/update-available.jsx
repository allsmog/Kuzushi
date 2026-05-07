// update-available + version-mismatch.

function UpdateAvailableView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('log','14:43:01',[m(' background check · '), p('crates.io'), m(' · '),
      p('release-feed.kuzushi.dev'), m(' · '), [' new version ', 'c-warn']], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ['┌─ ', 'c-subtle'], ['UPDATE AVAILABLE ', 'c-warn'],
      ['─'.repeat(W - 6 - 17), 'c-subtle'], ['┐', 'c-subtle']], W, 'top'),
    window.row([T('   '), ['│ ', 'c-subtle'],
      [' kuzushi 0.18.2 → 0.19.0  ·  released 2026-05-04  ·  3 days ago'.padEnd(W - 8, ' '), 'c-primary'],
      [' │', 'c-subtle']], W, 'r1'),
    window.row([T('   '), ['│ ', 'c-subtle'],
      [' channel stable  ·  signed by kuzushi-release@trail-of-bits.com'.padEnd(W - 8, ' '), 'c-muted'],
      [' │', 'c-subtle']], W, 'r2'),
    window.row([T('   '), ['└', 'c-subtle'], ['─'.repeat(W - 6), 'c-subtle'], ['┘', 'c-subtle']], W, 'bot'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('HIGHLIGHTS · 0.19.0', W, 's1'),
    window.row([T('   '), [' + ', 'c-success'], m('  '), p('agentic-sast'),     m('     cross-language taint (py↔ts) by default')], W, 'h1'),
    window.row([T('   '), [' + ', 'c-success'], m('  '), p('verify'),           m('           PoC replay against ephemeral sandbox')], W, 'h2'),
    window.row([T('   '), [' + ', 'c-success'], m('  '), p('threat-model'),     m('     PASTA + STRIDE merged into single tool')], W, 'h3'),
    window.row([T('   '), [' Δ ', 'c-warn'],    m('  '), p('options.toml'),     m('     migrating · '), p('TARGET'), m(' renamed to '), p('WORKSPACE'),
      m(' (alias kept until 0.21)')], W, 'h4'),
    window.row([T('   '), [' Δ ', 'c-warn'],    m('  '), p('actors.toml'),      m('      role '), p('redteam'), m(' renamed to '), p('attacker_aux')], W, 'h5'),
    window.row([T('   '), [' ✗ ', 'c-danger'],  m('  '), p('removed'),          m('          '), p('--legacy-json'), m(' (deprecated since 0.16)')], W, 'h6'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('VERSION MISMATCH · this workspace', W, 's2'),
    window.row([T('   '), m('binary             '), p('0.18.2')], W, 'm1'),
    window.row([T('   '), m('workspace schema   '), p('v6'), m('      ('), p('.kuzushi/v2/schema-version'), m(')')], W, 'm2'),
    window.row([T('   '), m('binary expects     '), p('v6'), m('      '), [' ✓ compatible ', 'c-success']], W, 'm3'),
    window.row([T('   '), m('0.19 expects       '), p('v7'), m('      '), [' ! migration on first launch ', 'c-warn']], W, 'm4'),
    window.row([T('   '), m('migration plan     '), p('rewrite findings.sqlite3 (38 rows · ~2s)  +  rename TARGET key in options.toml')], W, 'm5'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('OPTIONS', W, 's3'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('/update'),
      m('             pull 0.19.0 · auto-migrate · prompt before destructive')], W, 'o1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('/update --dry-run'),
      m('   show migration delta without writing')], W, 'o2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('/update --pin 0.18.2'),
      m(' stay on this version · suppress checks 7d')], W, 'o3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), a('/changelog'),
      m('         full 0.19.0 notes')], W, 'o4'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','14:43:02',[m(' '), [' note ', 'c-warn'],
      m(' if you are mid-pentest, '), a('--pin'), m(' is the safe choice')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /update · 0.18.2 → 0.19.0">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$0.41' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'update available · 0.19.0 · schema v6 → v7', findings: 38,
        keybinds: [['/update','pull'],['--dry-run','preview'],['--pin','stay'],['/changelog','notes']],
      })}
    </window.TermFrame>
  );
}
window.UpdateAvailableView = UpdateAvailableView;
