// /use chrome-rce · target picker

function ChromeRceTargetView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function tgt(focused, idx, name, ver, channel, kev) {
    const iCell = (' ' + idx + ' ').slice(0, 4);
    const nCell = (name + ' '.repeat(34)).slice(0, 30);
    const vCell = (ver + ' '.repeat(18)).slice(0, 14);
    const cCell = (channel + ' '.repeat(14)).slice(0, 12);
    const kCell = kev;
    if (focused) {
      const text = ' ' + iCell + nCell + vCell + cCell + kCell;
      return <span className="row" key={idx}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [iCell, 'c-accent'],
      [nCell, 'c-primary'],
      [vCell, 'c-muted'],
      [cCell, 'c-muted'],
      [kCell, kev.startsWith('0') ? 'c-success' : 'c-danger'],
    ], W, idx);
  }

  const lines = [
    window.logLine('in','15:58:01',[m(' /use chrome-rce')], W, 'l1'),
    window.row([T('  '), m('mode  '), p('research'),
      m('  ·  '), p('sandbox-only'),  m('  ·  '),
      p('targets are picked from your fleet inventory · zero outbound to anything else')], W, 'h0'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('TARGETS · 7 chrome builds in your fleet · pick one', W, 's1'),
    window.row([
      ['    ', null],
      [(' #' + ' '.repeat(2)).slice(0, 4), 'c-label'],
      [('build' + ' '.repeat(30)).slice(0, 30), 'c-label'],
      [('version' + ' '.repeat(14)).slice(0, 14), 'c-label'],
      [('channel' + ' '.repeat(12)).slice(0, 12), 'c-label'],
      ['kev', 'c-label'],
    ], W, 'h'),
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'r'),
    tgt(true,  '1', 'chromium-darwin-arm64',     '124.0.6367.118', 'stable',     '2 (cve-2026-2841 · 2842)'),
    tgt(false, '2', 'chromium-linux-x86_64',     '124.0.6367.118', 'stable',     '2 (cve-2026-2841 · 2842)'),
    tgt(false, '3', 'chrome-windows-x86_64',     '124.0.6367.119', 'stable',     '0'),
    tgt(false, '4', 'chrome-android-arm64',      '124.0.6367.113', 'stable',     '1 (cve-2026-2841)'),
    tgt(false, '5', 'edge-windows-x86_64',       '124.0.2478.71',  'stable',     '0'),
    tgt(false, '6', 'electron-32 · admin-app',   '32.1.2 (124)',   'pinned',     '2 (cve-2026-2841 · 2842)'),
    tgt(false, '7', 'electron-30 · refund-bot',  '30.4.0 (122)',   'pinned',     '4 (incl old days-of-week)'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('SELECTED · chromium-darwin-arm64 · 124.0.6367.118', W, 's2'),
    window.row([T('   '), m('binary    '), p('~/work/fleet/builds/chromium-darwin-arm64-124.0.6367.118.zip'),
      m(' (sha256 ab12…412e)')], W, 'd1'),
    window.row([T('   '), m('symbols   '), p('included'),  m(' · '), p('~ 480 MB unpacked'),
      m(' · '), p('mojom files indexed at 14:14')], W, 'd2'),
    window.row([T('   '), m('os matrix '), p('macos 14.4 + macos 15 (sandbox builds)')], W, 'd3'),
    window.row([T('   '), m('priors    '), p('CVE-2026-2841'),  m(' v8 type-confusion · '),
      p('CVE-2026-2842'),  m(' renderer ipc int-overflow')], W, 'd4'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('PLAN · what kuzushi will do once you confirm', W, 's3'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), p('spawn 2 sandboxes · macos 14.4 + 15')], W, 'p1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), p('attach kuzushi/chrome-rce harness'),
      m(' · v8 + ipc fuzzers · 14 plugins')], W, 'p2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), p('seed corpus from cve-2026-2841 + 2842 + 14 nearest neighbors')], W, 'p3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), p('budget: '),
      a('60m · $4.50'), m(' · stop on '),
      a('first-renderer-rce'), m(' or '), a('first-sandbox-escape')], W, 'p4'),
    window.row([T('   '), [' 5 ', 'c-accent'], m('  '), p('outputs to '),
      p('.kuzushi/runs/r-…/chrome-rce/'),  m(' · poc.html + min.repro + writeup.md')], W, 'p5'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('SAFETY', W, 's4'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('sandbox-only'),
      m(' · network egress denied · seed corpus loaded once at start')], W, 'sa1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('no live targets'),
      m(' · refused outright if you point this at https://*')], W, 'sa2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('crash artifacts'),
      m(' · stored in run dir · auto-redacted of /Users path')], W, 'sa3'),
    window.row([T('   '), [' · ', 'c-subtle'], m('  '), a('/auth confirm-redteam'),
      m(' would be required to extend to non-fleet builds')], W, 'sa4'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','15:58:14',[m(' '), a('y'), m(' start (60m / $4.50) · '),
      a('1..7'), m(' pick another target · '),
      a('e'), m(' edit budget · '),
      a('s'), m(' /show options chrome-rce · '),
      a('n'), m(' cancel')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /use chrome-rce · target picker">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'chrome-rce', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'chrome-rce · target picker · sandbox-only', findings: 38,
        promptModule: 'chrome-rce',
        keybinds: [['j/k','target'],['y','start'],['1..7','pick'],['e','budget'],['n','cancel']],
      })}
    </window.TermFrame>
  );
}
window.ChromeRceTargetView = ChromeRceTargetView;
