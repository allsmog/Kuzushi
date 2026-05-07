// Chrome-RCE view — checks for known browser-exploit chains in deployed
// embedded chromium / electron / webview surfaces. Native + review-trigger
// flow.

function ChromeRceView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const d = (t) => [t, 'c-danger'];
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

  function surface(name, ver, status, note) {
    const c = status === 'PATCHED' ? 'c-success' : status === 'EXPOSED' ? 'c-danger' : 'c-warn';
    return [
      [' ', null],
      [(name + ' '.repeat(28)).slice(0, 26), 'c-accent'],
      [(ver + ' '.repeat(14)).slice(0, 12), 'c-muted'],
      [(status + '   ').slice(0, 8), c],
      [note, 'c-primary'],
    ];
  }

  function trig(cve, name, where, exposed) {
    return [
      [' ', null],
      [(cve + ' '.repeat(16)).slice(0, 16), 'c-accent'],
      [(name + ' '.repeat(40)).slice(0, 36), 'c-primary'],
      [(where + ' '.repeat(28)).slice(0, 26), 'c-muted'],
      [exposed ? '★ EXPOSED' : '  not reachable', exposed ? 'c-danger' : 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in',  '15:51:08', [m(' /use '), a('chrome-rce')], W, 'l1'),
    window.logLine('in',  '15:51:14', [m(' /run '), a('scan --include electron,webview,puppeteer')], W, 'l2'),
    window.logLine('run', '15:51:14', [m(' chrome-rce:scan · enumerating embedded chromium surfaces')], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ...bar('manifest scan       ',  18,  18, 'done · 4 surfaces',   'c-success')], W, 'p1'),
    window.row([T('   '), ...bar('cve match (KEV)     ', 187, 187, 'done · 6 candidates', 'c-warn')], W, 'p2'),
    window.row([T('   '), ...bar('reachability        ',   6,   6, 'done · 2 reachable',  'c-warn')], W, 'p3'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('SURFACES · 4', W, 'sec-s'),
    window.row(surface('apps/desktop · electron',     '28.3.1',     'EXPOSED', 'main world preload exposes ipcRenderer'), W, 's1'),
    window.row(surface('apps/web · puppeteer pdf',    '21.6.0',     'OUTDATED','last bumped 9 months ago'), W, 's2'),
    window.row(surface('apps/admin · webview2',       'evergreen',  'PATCHED', 'auto-updates with windows'), W, 's3'),
    window.row(surface('jobs/scrape · headless-shell','120.0.6099', 'OUTDATED','pinned in scrape Dockerfile'), W, 's4'),
    window.blankRow(W, 'b3'),

    window.sectionHeader('TRIGGERS · 2 reachable · KEV', W, 'sec-t'),
    window.row(trig('CVE-2024-4671', 'V8 use-after-free in Visuals',  'apps/desktop · electron 28', true), W, 't1'),
    window.row(trig('CVE-2024-4761', 'V8 OOB write in V8 inline cache','jobs/scrape · 120.0.6099',   true), W, 't2'),
    window.row(trig('CVE-2024-3914', 'WebRTC heap-overflow',           'apps/web · puppeteer 21',    false), W, 't3'),
    window.row(trig('CVE-2024-2887', 'WebAssembly type confusion',     'jobs/scrape',                false), W, 't4'),
    window.row([T('   '), m('   … 2 more · '), a('/show triggers all')], W, 't-more'),
    window.blankRow(W, 'b4'),

    window.sectionHeader('REVIEW-TRIGGER · electron preload', W, 'sec-rt'),
    window.row([T('   '), m('the preload at '), p('apps/desktop/preload.js:14'), m(' bridges '), w('ipcRenderer.invoke'), m(' to the renderer.')], W, 'rt1'),
    window.row([T('   '), m('a renderer compromised via '), a('CVE-2024-4671'), m(' can call '), w('shell.openExternal'), m(' on the host.')], W, 'rt2'),
    window.row([T('   '), m('mitigation: '), p('contextIsolation=true'), m(' + drop '), p('shell.openExternal'), m(' from the bridge whitelist')], W, 'rt3'),
    window.blankRow(W, 'b5'),

    window.logLine('agent', '15:51:48', [m(' bump electron to '), p('28.3.3'), m(' (closes 4671) and ship in next desktop release.')], W, 'l-end'),
    window.logLine('log', '15:51:48', [m(' wrote '), p('.kuzushi/runs/.../chrome-rce.json'), m(' · '), p('persisted 2 findings')], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · chrome-rce · scan + review-trigger">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'chrome-rce', cost: '$0.09' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'chrome-rce (done) · 2 reachable KEV', findings: 2,
        promptModule: 'chrome-rce',
        keybinds: [
          ['/show', 'triggers all'], ['/use', 'patch'],
          ['/chrome-rce', 'review-trigger'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.ChromeRceView = ChromeRceView;
