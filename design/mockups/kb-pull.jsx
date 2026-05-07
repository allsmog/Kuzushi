// /kb pull · advisory feed pull

function KbPullView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function bar(label, done, total, status, color) {
    const w = 26;
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

  const lines = [
    window.logLine('in','14:56:01',[m(' /kb pull '), a('all')], W, 'l1'),
    window.logLine('run','14:56:01',[m(' destination '), p('~/.kuzushi/v2/kb/'),
      m(' · 4 feeds · ETag honored')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('kev (cisa)        ', 1284, 1284, 'done · 0 new',                                'c-success')], W, 'k1'),
    window.row([T('   '), ...bar('nvd (since 30d)   ',  482, 482,  'done · 41 new',                               'c-success')], W, 'k2'),
    window.row([T('   '), ...bar('cwe (taxonomy)    ', 1402, 1402, 'done · cached',                                'c-muted')], W, 'k3'),
    window.row([T('   '), ...bar('attck (mitre)     ',  211, 638, 'fetching · 412 KB/s',                          'c-warn')], W, 'k4'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('NEW · 41 advisories', W, 's1'),
    window.row([T('   '), p('CVE-2026-3142'), m('  hi  · libxml2 · UAF in xmlReadDoc            · added 2026-05-04')], W, 'a1'),
    window.row([T('   '), p('CVE-2026-3098'), m('  cr  · openssl · plaintext recovery on ECDSA  · added 2026-05-03')], W, 'a2'),
    window.row([T('   '), p('CVE-2026-2941'), m('  hi  · postgres · auth bypass under PAM       · added 2026-05-02')], W, 'a3'),
    window.row([T('   '), p('CVE-2026-2877'), m('  med · curl · CRLF injection in custom-header · added 2026-05-02')], W, 'a4'),
    window.row([T('   '), p('CVE-2026-2841'), m('  cr  · jenkins · agent RCE via WS upgrade     · added 2026-05-01')], W, 'a5'),
    window.row([T('   '), m('   … '), p('36 more'), m(' · '), a('/kb show --since 7d --severity high+'), m(' to filter')], W, 'a6'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('IMPACT · against this workspace', W, 's2'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('CVE-2026-2941'), m(' · postgres · matched lockfile entry '), p('postgres-rs 0.7.21')], W, 'i1'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('CVE-2026-2877'), m(' · curl ·     matched dep '), p('reqwest → curl 8.6.0')], W, 'i2'),
    window.row([T('   '), [' · ', 'c-subtle'], m('  '), p('CVE-2026-3098'), m(' · openssl · uses rustls fork — not affected')], W, 'i3'),
    window.blankRow(W, 'b4'),
    window.row([T('   '), [' i ', 'c-accent'], m('  pinning matters: '), a('/use ndiff CVE-2026-2941'),
      m(' will run a variant hunt against your tree')], W, 'in1'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','14:56:18',[m(' '), a('/kb pull --schedule daily'),
      m('  cron via systemd / launchd · auto-run on /scan if stale')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /kb pull · 41 new advisories">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'kb', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'kb · 41 new · attck pulling 33%', findings: 38,
        promptModule: 'kb',
        keybinds: [['/kb show','filter'],['/use ndiff','hunt variant'],['--schedule','cron']],
      })}
    </window.TermFrame>
  );
}
window.KbPullView = KbPullView;
